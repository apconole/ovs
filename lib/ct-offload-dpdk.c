/*
 * Copyright (c) 2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#ifdef DPDK_NETDEV

#include <rte_flow.h>

#include "cmap.h"
#include "conntrack-private.h"
#include "conntrack-tcp.h"
#include "ct-offload.h"
#include "hash.h"
#include "netdev-dpdk.h"
#include "netdev.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"

#include "openvswitch/types.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_offload_dpdk);

/* Maximum items/actions used when constructing rte_flow rules for CT. */
#define CT_DPDK_MAX_ITEMS   6
#define CT_DPDK_MAX_ACTIONS 5   /* CONNTRACK + AGE + PASSTHRU + END, plus 1 */

/* AGE timeout passed to the hardware.  Set large so the hardware rule
 * outlives the software connection; OVS software expiration controls the
 * real lifetime via conn_update queries. */
#define CT_DPDK_AGE_TIMEOUT_SEC  3600u   /* 1 hour */


/* -----------------------------------------------------------------------
 * Per-connection state
 * ----------------------------------------------------------------------- */

/* One entry per offloaded conntrack connection. */
struct ct_dpdk_conn {
    struct cmap_node   node;        /* In ct_dpdk_map, keyed by conn ptr. */
    const struct conn *conn;        /* Conntrack entry — key for lookup. */
    struct rte_flow   *fwd_flow;    /* rte_flow for the forward direction. */
    struct rte_flow   *rev_flow;    /* rte_flow for the reply direction. */
    struct netdev     *netdev;      /* Held reference for flow destroy. */
    int                port_id;     /* DPDK ethdev port_id for rte_flow_query. */
};

/* Mutex serialises cmap modifications (insert/remove).  Reads are lockless
 * via the cmap's own RCU mechanism. */
static struct ovs_mutex ct_dpdk_mutex = OVS_MUTEX_INITIALIZER;
static struct cmap      ct_dpdk_map   = CMAP_INITIALIZER;


/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

static uint32_t
ct_dpdk_hash_conn(const struct conn *conn)
{
    return hash_pointer(conn, 0);
}

/* Lockless lookup — safe to call from any thread while holding an RCU
 * read-side critical section (which all OVS threads are implicitly in). */
static struct ct_dpdk_conn *
ct_dpdk_find(const struct conn *conn)
{
    struct ct_dpdk_conn *entry;
    uint32_t hash = ct_dpdk_hash_conn(conn);

    CMAP_FOR_EACH_WITH_HASH (entry, node, hash, &ct_dpdk_map) {
        if (entry->conn == conn) {
            return entry;
        }
    }
    return NULL;
}

/* Destroy the rte_flow handles in 'entry' and release its resources.
 * Called via ovsrcu_postpone so that any concurrent reader that still holds
 * a pointer to the entry can safely finish before the memory is freed. */
static void
ct_dpdk_destroy_entry(void *entry_)
{
    struct ct_dpdk_conn *entry = entry_;
    struct rte_flow_error error;

    if (entry->fwd_flow) {
        netdev_dpdk_rte_flow_destroy(entry->netdev, entry->fwd_flow, &error);
    }
    if (entry->rev_flow) {
        netdev_dpdk_rte_flow_destroy(entry->netdev, entry->rev_flow, &error);
    }
    netdev_close(entry->netdev);
    free(entry);
}


/* -----------------------------------------------------------------------
 * Pattern and action construction
 * ----------------------------------------------------------------------- */

/* All spec/mask storage for a single direction's rte_flow pattern.
 * Kept on the stack; rte_flow_create copies the data internally. */
struct ct_dpdk_pattern {
    struct rte_flow_item items[CT_DPDK_MAX_ITEMS];
    /* IP layer: only one of ipv4/ipv6 is populated. */
    struct rte_flow_item_ipv4 ipv4[2]; /* [0]=spec [1]=mask */
    struct rte_flow_item_ipv6 ipv6[2];
    /* L4 layer: only one of tcp/udp is populated. */
    struct rte_flow_item_tcp  tcp[2];
    struct rte_flow_item_udp  udp[2];
    int n_items;
};

static void
ct_dpdk_pattern_add(struct ct_dpdk_pattern *p,
                    enum rte_flow_item_type type,
                    const void *spec, const void *mask)
{
    struct rte_flow_item *item = &p->items[p->n_items++];

    item->type = type;
    item->spec = spec;
    item->mask = mask;
    item->last = NULL;
}

/* Build an rte_flow match pattern from a conntrack key.
 * Returns true on success, false if the key's protocol is unsupported. */
static bool
ct_dpdk_build_pattern(struct ct_dpdk_pattern *p, const struct conn_key *key)
{
    memset(p, 0, sizeof *p);

    /* ETH — wildcarded; we match at the IP level. */
    ct_dpdk_pattern_add(p, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);

    /* IP layer. */
    if (key->dl_type == htons(ETH_TYPE_IP)) {
        p->ipv4[0].hdr.src_addr = key->src.addr.ipv4;
        p->ipv4[0].hdr.dst_addr = key->dst.addr.ipv4;
        p->ipv4[1].hdr.src_addr = OVS_BE32_MAX;
        p->ipv4[1].hdr.dst_addr = OVS_BE32_MAX;
        ct_dpdk_pattern_add(p, RTE_FLOW_ITEM_TYPE_IPV4,
                            &p->ipv4[0], &p->ipv4[1]);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)) {
        memcpy(&p->ipv6[0].hdr.src_addr, &key->src.addr.ipv6,
               sizeof p->ipv6[0].hdr.src_addr);
        memcpy(&p->ipv6[0].hdr.dst_addr, &key->dst.addr.ipv6,
               sizeof p->ipv6[0].hdr.dst_addr);
        memset(&p->ipv6[1].hdr.src_addr, 0xFF,
               sizeof p->ipv6[1].hdr.src_addr);
        memset(&p->ipv6[1].hdr.dst_addr, 0xFF,
               sizeof p->ipv6[1].hdr.dst_addr);
        ct_dpdk_pattern_add(p, RTE_FLOW_ITEM_TYPE_IPV6,
                            &p->ipv6[0], &p->ipv6[1]);
    } else {
        return false;
    }

    /* L4 layer. */
    if (key->nw_proto == IPPROTO_TCP) {
        p->tcp[0].hdr.src_port = key->src.port;
        p->tcp[0].hdr.dst_port = key->dst.port;
        p->tcp[1].hdr.src_port = OVS_BE16_MAX;
        p->tcp[1].hdr.dst_port = OVS_BE16_MAX;
        ct_dpdk_pattern_add(p, RTE_FLOW_ITEM_TYPE_TCP,
                            &p->tcp[0], &p->tcp[1]);
    } else if (key->nw_proto == IPPROTO_UDP) {
        p->udp[0].hdr.src_port = key->src.port;
        p->udp[0].hdr.dst_port = key->dst.port;
        p->udp[1].hdr.src_port = OVS_BE16_MAX;
        p->udp[1].hdr.dst_port = OVS_BE16_MAX;
        ct_dpdk_pattern_add(p, RTE_FLOW_ITEM_TYPE_UDP,
                            &p->udp[0], &p->udp[1]);
    } else {
        return false;
    }

    ct_dpdk_pattern_add(p, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
    return true;
}

/* Map a conntrack TCP state to the DPDK rte_flow conntrack state enum. */
static enum rte_flow_conntrack_state
ct_dpdk_tcp_state(enum ct_dpif_tcp_state s)
{
    switch (s) {
    case CT_DPIF_TCPS_SYN_SENT:
    case CT_DPIF_TCPS_SYN_RECV:
        return RTE_FLOW_CONNTRACK_STATE_SYN_RECV;
    case CT_DPIF_TCPS_ESTABLISHED:
        return RTE_FLOW_CONNTRACK_STATE_ESTABLISHED;
    case CT_DPIF_TCPS_FIN_WAIT_1:
    case CT_DPIF_TCPS_FIN_WAIT_2:
    case CT_DPIF_TCPS_CLOSING:
        return RTE_FLOW_CONNTRACK_STATE_FIN_WAIT;
    case CT_DPIF_TCPS_CLOSE_WAIT:
        return RTE_FLOW_CONNTRACK_STATE_CLOSE_WAIT;
    case CT_DPIF_TCPS_LAST_ACK:
        return RTE_FLOW_CONNTRACK_STATE_LAST_ACK;
    case CT_DPIF_TCPS_TIME_WAIT:
        return RTE_FLOW_CONNTRACK_STATE_TIME_WAIT;
    case CT_DPIF_TCPS_CLOSED:
    case CT_DPIF_TCPS_LISTEN:
    case CT_DPIF_TCPS_MAX_NUM:
    default:
        return RTE_FLOW_CONNTRACK_STATE_CLOSE_WAIT;
    }
}

/* Populate an rte_flow_action_conntrack from the software TCP state.
 * 'is_original_dir': 1 for the forward (original) flow, 0 for the reply. */
static void
ct_dpdk_build_conntrack_action(struct rte_flow_action_conntrack *ct_action,
                               const struct conn_tcp_state *tcp_state,
                               int is_original_dir)
{
    const struct tcp_peer *orig  = &tcp_state->peer[CT_DIR_FWD];
    const struct tcp_peer *reply = &tcp_state->peer[CT_DIR_REV];

    memset(ct_action, 0, sizeof *ct_action);

    ct_action->is_original_dir  = is_original_dir;
    ct_action->enable           = 1;
    ct_action->live_connection  = 1;
    ct_action->state            = ct_dpdk_tcp_state(orig->state);

    /* Original direction peer parameters. */
    ct_action->original_dir.scale     = orig->wscale & CT_WSCALE_MASK;
    ct_action->original_dir.sent_end  = orig->seqlo;
    ct_action->original_dir.reply_end = orig->seqhi;
    ct_action->original_dir.max_win   = orig->max_win;

    /* Reply direction peer parameters. */
    ct_action->reply_dir.scale     = reply->wscale & CT_WSCALE_MASK;
    ct_action->reply_dir.sent_end  = reply->seqlo;
    ct_action->reply_dir.reply_end = reply->seqhi;
    ct_action->reply_dir.max_win   = reply->max_win;
}

/* Install a TCP conntrack rte_flow rule: CONNTRACK + AGE + PASSTHRU + END.
 *
 * 'is_original_dir' distinguishes the forward (1) from the reply (0) rule.
 * The CONNTRACK action tells the hardware the current TCP state so it can
 * track sequence numbers and transitions autonomously.  The AGE action lets
 * us later query when the flow last saw traffic.  PASSTHRU hands the packet
 * back to the normal software datapath. */
static struct rte_flow *
ct_dpdk_install_tcp_flow(struct netdev *netdev,
                         const struct conn_key *key,
                         const struct conn *conn,
                         const struct conn_tcp_state *tcp_state,
                         int is_original_dir)
{
    struct ct_dpdk_pattern pattern;
    struct rte_flow_action_conntrack ct_spec;
    struct rte_flow_action_age age_spec;
    struct rte_flow_action actions[CT_DPDK_MAX_ACTIONS];
    const struct rte_flow_attr attr = { .ingress = 1 };
    struct rte_flow_error error;
    int n = 0;

    if (!ct_dpdk_build_pattern(&pattern, key)) {
        return NULL;
    }

    ct_dpdk_build_conntrack_action(&ct_spec, tcp_state, is_original_dir);
    actions[n].type = RTE_FLOW_ACTION_TYPE_CONNTRACK;
    actions[n].conf = &ct_spec;
    n++;

    memset(&age_spec, 0, sizeof age_spec);
    age_spec.timeout = CT_DPDK_AGE_TIMEOUT_SEC;
    age_spec.context = CONST_CAST(struct conn *, conn);
    actions[n].type = RTE_FLOW_ACTION_TYPE_AGE;
    actions[n].conf = &age_spec;
    n++;

    actions[n].type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
    actions[n].conf = NULL;
    n++;

    actions[n].type = RTE_FLOW_ACTION_TYPE_END;
    actions[n].conf = NULL;

    struct rte_flow *flow = netdev_dpdk_rte_flow_create(netdev, &attr,
                                                        pattern.items,
                                                        actions, &error);
    if (!flow) {
        VLOG_DBG("ct_dpdk: TCP rte_flow_create failed (dir=%d): %s",
                 is_original_dir,
                 error.message ? error.message : "unknown");
    }
    return flow;
}

/* Install a UDP (or other stateless) rte_flow rule: AGE + PASSTHRU + END.
 *
 * UDP has no hardware state machine, so we only attach an AGE action for
 * last-traffic detection. */
static struct rte_flow *
ct_dpdk_install_udp_flow(struct netdev *netdev,
                         const struct conn_key *key,
                         const struct conn *conn)
{
    struct ct_dpdk_pattern pattern;
    struct rte_flow_action_age age_spec;
    struct rte_flow_action actions[CT_DPDK_MAX_ACTIONS];
    const struct rte_flow_attr attr = { .ingress = 1 };
    struct rte_flow_error error;
    int n = 0;

    if (!ct_dpdk_build_pattern(&pattern, key)) {
        return NULL;
    }

    memset(&age_spec, 0, sizeof age_spec);
    age_spec.timeout = CT_DPDK_AGE_TIMEOUT_SEC;
    age_spec.context = CONST_CAST(struct conn *, conn);
    actions[n].type = RTE_FLOW_ACTION_TYPE_AGE;
    actions[n].conf = &age_spec;
    n++;

    actions[n].type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
    actions[n].conf = NULL;
    n++;

    actions[n].type = RTE_FLOW_ACTION_TYPE_END;
    actions[n].conf = NULL;

    struct rte_flow *flow = netdev_dpdk_rte_flow_create(netdev, &attr,
                                                        pattern.items,
                                                        actions, &error);
    if (!flow) {
        VLOG_DBG("ct_dpdk: UDP rte_flow_create failed: %s",
                 error.message ? error.message : "unknown");
    }
    return flow;
}


/* -----------------------------------------------------------------------
 * ct_offload_class callbacks
 * ----------------------------------------------------------------------- */

static bool
ct_dpdk_can_offload(const struct ct_offload_ctx *ctx)
{
    const struct conn_key *key;
    uint8_t proto;

    if (!ctx->netdev_in
        || !netdev_dpdk_flow_api_supported(ctx->netdev_in, false)) {
        return false;
    }

    key   = &ctx->conn->key_node[CT_DIR_FWD].key;
    proto = key->nw_proto;
    return proto == IPPROTO_TCP || proto == IPPROTO_UDP;
}

static int
ct_dpdk_conn_add(const struct ct_offload_ctx *ctx)
{
    const struct conn *conn = ctx->conn;
    const struct conn_key *fwd_key = &conn->key_node[CT_DIR_FWD].key;
    struct ct_dpdk_conn *entry;
    int port_id;

    port_id = netdev_dpdk_get_port_id(ctx->netdev_in);
    if (port_id < 0) {
        return ENODEV;
    }

    /* For the reply direction use netdev_out if available, else same port. */
    struct netdev *rev_netdev = ctx->netdev_out
                                ? ctx->netdev_out
                                : ctx->netdev_in;

    entry = xzalloc(sizeof *entry);
    entry->conn    = conn;
    entry->netdev  = netdev_ref(ctx->netdev_in);
    entry->port_id = port_id;

    if (fwd_key->nw_proto == IPPROTO_TCP) {
        const struct conn_tcp_state *tcp_state = conn_tcp_state_get(conn);

        if (!tcp_state) {
            /* TCP state not available — fall back gracefully. */
            netdev_close(entry->netdev);
            free(entry);
            return EOPNOTSUPP;
        }

        entry->fwd_flow = ct_dpdk_install_tcp_flow(
            ctx->netdev_in,
            &conn->key_node[CT_DIR_FWD].key,
            conn, tcp_state, 1 /* is_original_dir */);
        entry->rev_flow = ct_dpdk_install_tcp_flow(
            rev_netdev,
            &conn->key_node[CT_DIR_REV].key,
            conn, tcp_state, 0 /* reply dir */);
    } else {
        entry->fwd_flow = ct_dpdk_install_udp_flow(
            ctx->netdev_in,
            &conn->key_node[CT_DIR_FWD].key,
            conn);
        entry->rev_flow = ct_dpdk_install_udp_flow(
            rev_netdev,
            &conn->key_node[CT_DIR_REV].key,
            conn);
    }

    if (!entry->fwd_flow && !entry->rev_flow) {
        netdev_close(entry->netdev);
        free(entry);
        return EOPNOTSUPP;
    }

    ovs_mutex_lock(&ct_dpdk_mutex);
    cmap_insert(&ct_dpdk_map, &entry->node, ct_dpdk_hash_conn(conn));
    ovs_mutex_unlock(&ct_dpdk_mutex);

    return 0;
}

static void
ct_dpdk_conn_del(const struct ct_offload_ctx *ctx)
{
    struct ct_dpdk_conn *entry = ct_dpdk_find(ctx->conn);

    if (!entry) {
        return;
    }

    ovs_mutex_lock(&ct_dpdk_mutex);
    cmap_remove(&ct_dpdk_map, &entry->node, ct_dpdk_hash_conn(ctx->conn));
    ovs_mutex_unlock(&ct_dpdk_mutex);

    ovsrcu_postpone(ct_dpdk_destroy_entry, entry);
}

/* Query the AGE action on 'flow' and return the last-hit time in
 * milliseconds since epoch, or 0 if the result is not available. */
static long long
ct_dpdk_query_age(int port_id, struct rte_flow *flow)
{
    const struct rte_flow_action age_query[] = {
        { .type = RTE_FLOW_ACTION_TYPE_AGE },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_query_age result = { 0 };
    struct rte_flow_error error;

    if (rte_flow_query(port_id, flow, age_query, &result, &error)) {
        return 0;
    }

    if (!result.sec_since_last_hit_valid) {
        return 0;
    }

    return time_msec() - (long long)result.sec_since_last_hit * 1000;
}

static long long
ct_dpdk_conn_update(const struct ct_offload_ctx *ctx)
{
    struct ct_dpdk_conn *entry = ct_dpdk_find(ctx->conn);
    long long fwd_ts = 0;
    long long rev_ts = 0;

    if (!entry) {
        return 0;
    }

    if (entry->fwd_flow) {
        fwd_ts = ct_dpdk_query_age(entry->port_id, entry->fwd_flow);
    }
    if (entry->rev_flow) {
        rev_ts = ct_dpdk_query_age(entry->port_id, entry->rev_flow);
    }

    /* Return the most recent (largest) timestamp across both directions. */
    return MAX(fwd_ts, rev_ts);
}

static void
ct_dpdk_flush(void)
{
    struct ct_dpdk_conn *entry;

    /* CMAP_FOR_EACH is RCU-safe under concurrent cmap_remove calls. */
    CMAP_FOR_EACH (entry, node, &ct_dpdk_map) {
        ovs_mutex_lock(&ct_dpdk_mutex);
        cmap_remove(&ct_dpdk_map, &entry->node,
                    ct_dpdk_hash_conn(entry->conn));
        ovs_mutex_unlock(&ct_dpdk_mutex);
        ovsrcu_postpone(ct_dpdk_destroy_entry, entry);
    }
}

/* -----------------------------------------------------------------------
 * Provider class definition and registration
 * ----------------------------------------------------------------------- */

const struct ct_offload_class ct_offload_dpdk_class = {
    .name         = "dpdk",
    .init         = NULL,
    .conn_add     = ct_dpdk_conn_add,
    .conn_del     = ct_dpdk_conn_del,
    .conn_update  = ct_dpdk_conn_update,
    .can_offload  = ct_dpdk_can_offload,
    .flush        = ct_dpdk_flush,
};

#endif /* DPDK_NETDEV */

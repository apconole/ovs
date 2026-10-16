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

#include <errno.h>

#include "ct-offload-dummy.h"

#include "conntrack-private.h"
#include "coverage.h"
#include "ct-offload.h"
#include "dummy.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "timeval.h"
#include "unixctl.h"

VLOG_DEFINE_THIS_MODULE(ct_offload_dummy);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

COVERAGE_DEFINE(ct_offload_dummy_add);
COVERAGE_DEFINE(ct_offload_dummy_del);
COVERAGE_DEFINE(ct_offload_dummy_upd);
COVERAGE_DEFINE(ct_offload_dummy_est);

/* Test knobs for UPD reporting: "active" (default) reports a fresh
 * last_used (connections never expire in software), "idle" reports no
 * activity (normal expiry), "evicted" reports ENOENT (demotion). */
static atomic_bool dummy_hw_idle;
static atomic_bool dummy_hw_evicted;

/* Per-connection state.  Port names are copies: ctx.netdev_in is only
 * valid during the submit, and ports may be deleted while tracked. */
struct ct_dummy_entry {
    struct ovs_list list_node;
    const struct conn *conn;
    char *fwd_in_name;              /* Input port of the original
                                     * direction. */
    char *rev_in_name;              /* Input port of the reply
                                     * direction. */
};

/* Frees 'e' and the strings it owns. */
static void
dummy_entry_destroy(struct ct_dummy_entry *e)
{
    free(e->fwd_in_name);
    free(e->rev_in_name);
    free(e);
}

/* List of offloaded connections, protected by dummy_mutex. */
static struct ovs_mutex dummy_mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_list dummy_conns OVS_GUARDED_BY(dummy_mutex)
    = OVS_LIST_INITIALIZER(&dummy_conns);

/* Lookup must be called with dummy_mutex held. */
static struct ct_dummy_entry *
dummy_find__(const struct conn *conn)
    OVS_REQUIRES(dummy_mutex)
{
    struct ct_dummy_entry *e;

    LIST_FOR_EACH (e, list_node, &dummy_conns) {
        if (e->conn == conn) {
            return e;
        }
    }
    return NULL;
}

/* Returns 'name', or "(nil)" if it is NULL. */
static const char *
dummy_netdev_name(const char *name)
{
    return name ? name : "(nil)";
}

/* Only dummy-netdev ports, mirroring the dpif-offload-dummy
 * can_offload check. */
static bool
dummy_netdev_offloadable(const struct netdev *netdev)
{
    return netdev && is_dummy_netdev_class(netdev_get_class(netdev));
}

static bool
dummy_flow_might_offload(const struct ct_offload_flow_ctx *ctx)
{
    return dummy_netdev_offloadable(ctx->netdev_in);
}

static void
dummy_op_add(struct ct_offload_op *op)
{
    const struct ct_offload_ctx *ctx = &op->ctx;

    ovs_assert(ctx->conn);

    if (!dummy_netdev_offloadable(ctx->netdev_in)) {
        /* Decline: leave the pre-filled result untouched. */
        return;
    }

    char *in_name = ctx->netdev_in
                    ? xstrdup(netdev_get_name(ctx->netdev_in)) : NULL;

    struct ct_dummy_entry *e = xmalloc(sizeof *e);

    e->conn = ctx->conn;
    e->fwd_in_name = in_name;
    e->rev_in_name = NULL;

    ovs_mutex_lock(&dummy_mutex);
    if (dummy_find__(ctx->conn)) {
        ovs_mutex_unlock(&dummy_mutex);
        dummy_entry_destroy(e);
        VLOG_WARN_RL(&rl, "conn %p added twice", ctx->conn);
        op->error = EEXIST;
        return;
    }
    ovs_list_push_back(&dummy_conns, &e->list_node);
    ovs_mutex_unlock(&dummy_mutex);

    op->error = 0;

    COVERAGE_INC(ct_offload_dummy_add);
    VLOG_DBG("conn add: conn=%p fwd_in=%s", ctx->conn,
             dummy_netdev_name(in_name));
}

static void
dummy_op_del(struct ct_offload_op *op)
{
    const struct ct_offload_ctx *ctx = &op->ctx;

    ovs_assert(ctx->conn);

    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e = dummy_find__(ctx->conn);

    if (e) {
        ovs_list_remove(&e->list_node);
        dummy_entry_destroy(e);
    }
    ovs_mutex_unlock(&dummy_mutex);

    op->error = 0;
    COVERAGE_INC(ct_offload_dummy_del);
    VLOG_DBG("conn del: conn=%p", ctx->conn);
}

static void
dummy_op_establish(struct ct_offload_op *op)
{
    const struct ct_offload_ctx *ctx = &op->ctx;

    ovs_assert(ctx->conn);

    char *rev_in_name = ctx->netdev_in
                        ? xstrdup(netdev_get_name(ctx->netdev_in)) : NULL;
    char *log_fwd_name = NULL;
    char *log_rev_name = NULL;

    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e = dummy_find__(ctx->conn);

    if (e) {
        if (!e->rev_in_name) {
            e->rev_in_name = rev_in_name;
            rev_in_name = NULL;        /* Ownership transferred to 'e'. */
            op->hw_confirmed = true;
            COVERAGE_INC(ct_offload_dummy_est);
        }
        log_fwd_name = e->fwd_in_name ? xstrdup(e->fwd_in_name) : NULL;
        log_rev_name = e->rev_in_name ? xstrdup(e->rev_in_name) : NULL;
    }
    ovs_mutex_unlock(&dummy_mutex);

    VLOG_DBG("conn established: conn=%p fwd_in=%s rev_in=%s",
             ctx->conn, dummy_netdev_name(log_fwd_name),
             dummy_netdev_name(log_rev_name));
    free(log_fwd_name);
    free(log_rev_name);
    free(rev_in_name);
}

static void
dummy_op_upd(struct ct_offload_op *op)
{
    const struct ct_offload_ctx *ctx = &op->ctx;

    ovs_assert(ctx->conn);

    ovs_mutex_lock(&dummy_mutex);
    bool found = dummy_find__(ctx->conn) != NULL;
    ovs_mutex_unlock(&dummy_mutex);

    if (found) {
        bool hw_evicted, hw_idle;

        atomic_read_relaxed(&dummy_hw_evicted, &hw_evicted);
        atomic_read_relaxed(&dummy_hw_idle, &hw_idle);
        COVERAGE_INC(ct_offload_dummy_upd);
        if (hw_evicted) {
            op->error = ENOENT;
        } else {
            op->error = 0;
            op->last_used = hw_idle ? 0 : time_msec();
        }
    }
    VLOG_DBG("conn update: conn=%p last_used=%lld", ctx->conn,
             op->last_used);
}

static void
dummy_batch_submit(const struct ct_offload_op_batch *batch)
{
    struct ct_offload_op *op;

    CT_OFFLOAD_BATCH_OP_FOR_EACH (batch, i, op) {
        switch (op->type) {
        case CT_OFFLOAD_OP_ADD:
            dummy_op_add(op);
            break;
        case CT_OFFLOAD_OP_DEL:
            dummy_op_del(op);
            break;
        case CT_OFFLOAD_OP_UPD:
            dummy_op_upd(op);
            break;
        case CT_OFFLOAD_OP_ESTABLISHED:
            dummy_op_establish(op);
            break;
        }
    }
}

/* Drops all tracked connections on last close. */
static void
dummy_close(void)
{
    struct ct_dummy_entry *e;

    ovs_mutex_lock(&dummy_mutex);
    LIST_FOR_EACH_POP (e, list_node, &dummy_conns) {
        dummy_entry_destroy(e);
    }
    ovs_mutex_unlock(&dummy_mutex);
}

/* "ct-offload-dummy/set-hw-activity" (see the knobs above). */
static void
ct_offload_dummy_set_hw_activity(struct unixctl_conn *conn,
                                 int argc OVS_UNUSED,
                                 const char *argv[], void *aux OVS_UNUSED)
{
    if (!strcmp(argv[1], "active")) {
        atomic_store_relaxed(&dummy_hw_idle, false);
        atomic_store_relaxed(&dummy_hw_evicted, false);
    } else if (!strcmp(argv[1], "idle")) {
        atomic_store_relaxed(&dummy_hw_idle, true);
        atomic_store_relaxed(&dummy_hw_evicted, false);
    } else if (!strcmp(argv[1], "evicted")) {
        atomic_store_relaxed(&dummy_hw_evicted, true);
    } else {
        unixctl_command_reply_error(conn, "invalid mode; expected active, "
                                    "idle or evicted");
        return;
    }
    unixctl_command_reply(conn, NULL);
}

void
ct_offload_dummy_init(void)
{
    unixctl_command_register("ct-offload-dummy/set-hw-activity",
                             "active|idle|evicted", 1, 1,
                             ct_offload_dummy_set_hw_activity, NULL);
}

const struct ct_offload_class ct_offload_dummy_class = {
    .name         = "dummy",
    .open         = NULL,
    .close        = dummy_close,
    .batch_submit = dummy_batch_submit,
    .flow_might_offload = dummy_flow_might_offload,
};

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

#include "ct-offload-dummy.h"
#include "ct-offload.h"
#include "hash.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "timeval.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ct_offload_dummy);

/* -----------------------------------------------------------------------
 * Per-connection tracking
 * ----------------------------------------------------------------------- */

struct ct_dummy_entry {
    struct ovs_list   list_node;
    const struct conn *conn;
    struct netdev     *netdev_fwd_in;
    struct netdev     *netdev_rev_in;
};

/* ct-offload infrastructure guarantees that we get called under the offload
 * mutex, but the counters that we have are simple ints that can be erased
 * at any time from any thread, so we have this extra mutex for consistency.
 */
static struct ovs_mutex    dummy_mutex    = OVS_MUTEX_INITIALIZER;

/* Since this is a testing interface, we can use the above mutex when checking
 * the fake list of offloaded connections for other properties (like the
 * bidireactionality, etc).  A proper hardware offload implementation shouldn't
 * generally need this amount of critical sections.
 */
static struct ovs_list     dummy_conns    OVS_GUARDED_BY(dummy_mutex)
    = OVS_LIST_INITIALIZER(&dummy_conns);

static unsigned int n_added       = 0;
static unsigned int n_deleted     = 0;
static unsigned int n_updated     = 0;
static unsigned int n_established = 0;

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

static bool
dummy_can_offload(const struct ct_offload_ctx *ctx OVS_UNUSED)
{
    /* Always accept that we can offload in the dummy provider */
    return true;
}

static int
dummy_conn_add(const struct ct_offload_ctx *ctx)
{
    struct ct_dummy_entry *e = xmalloc(sizeof *e);

    e->conn = ctx->conn;
    e->netdev_fwd_in = ctx->netdev_in;
    e->netdev_rev_in = NULL;

    ovs_mutex_lock(&dummy_mutex);
    ovs_list_push_back(&dummy_conns, &e->list_node);
    n_added++;
    ovs_mutex_unlock(&dummy_mutex);

    VLOG_DBG("ct_offload_dummy: conn add: conn=%p, netdev_fwd_in=%p",
             ctx->conn, ctx->netdev_in);
    return 0;
}

static void
dummy_conn_del(const struct ct_offload_ctx *ctx)
{
    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e = dummy_find__(ctx->conn);

    if (e) {
        ovs_list_remove(&e->list_node);
        n_deleted++;
        free(e);
    }
    ovs_mutex_unlock(&dummy_mutex);

    VLOG_DBG("ct_offload_dummy: conn del: conn=%p", ctx->conn);
}

static void
dummy_conn_established(const struct ct_offload_ctx *ctx)
{
    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e = dummy_find__(ctx->conn);

    if (e && !e->netdev_rev_in) {
        e->netdev_rev_in = ctx->netdev_in;
        n_established++;
        VLOG_DBG("ct_offload_dummy: conn established: conn=%p "
                 "netdev_fwd_in=%p netdev_rev_in=%p",
                 ctx->conn, e->netdev_fwd_in, e->netdev_rev_in);
    }
    ovs_mutex_unlock(&dummy_mutex);
}

static long long
dummy_conn_update(const struct ct_offload_ctx *ctx)
{
    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e = dummy_find__(ctx->conn);

    if (!e) {
        ovs_mutex_unlock(&dummy_mutex);
        return 0;
    }

    n_updated++;
    ovs_mutex_unlock(&dummy_mutex);

    VLOG_DBG("ct_offload_dummy: conn update: conn=%p", ctx->conn);
    return time_msec();
}

static void
dummy_flush(void)
{
    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e;
    LIST_FOR_EACH_POP (e, list_node, &dummy_conns) {
        n_deleted++;
        free(e);
    }
    ovs_mutex_unlock(&dummy_mutex);
}

/* -----------------------------------------------------------------------
 * Provider class
 * ----------------------------------------------------------------------- */

const struct ct_offload_class ct_offload_dummy_class = {
    .name             = "dummy",
    .init             = NULL,
    .batch_submit     = NULL,
    .conn_add         = dummy_conn_add,
    .conn_del         = dummy_conn_del,
    .conn_update      = dummy_conn_update,
    .conn_established = dummy_conn_established,
    .can_offload      = dummy_can_offload,
    .flush            = dummy_flush,
};

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

void
ct_offload_dummy_register(void)
{
    ct_offload_dummy_reset_counters();
    ct_offload_register(&ct_offload_dummy_class);
}

void
ct_offload_dummy_unregister(void)
{
    /* Flush any leftover entries before unregistering so we do not leak. */
    dummy_flush();
    ct_offload_unregister(&ct_offload_dummy_class);
}

unsigned int
ct_offload_dummy_n_added(void)
{
    return n_added;
}

unsigned int
ct_offload_dummy_n_deleted(void)
{
    return n_deleted;
}

unsigned int
ct_offload_dummy_n_updated(void)
{
    return n_updated;
}

unsigned int
ct_offload_dummy_n_established(void)
{
    return n_established;
}

void
ct_offload_dummy_reset_counters(void)
{
    ovs_mutex_lock(&dummy_mutex);
    n_added       = 0;
    n_deleted     = 0;
    n_updated     = 0;
    n_established = 0;
    ovs_mutex_unlock(&dummy_mutex);
}

bool
ct_offload_dummy_contains(const struct conn *conn)
{
    ovs_mutex_lock(&dummy_mutex);
    bool found = dummy_find__(conn) != NULL;
    ovs_mutex_unlock(&dummy_mutex);
    return found;
}

/* Returns true if the dummy provider has seen both the forward-direction
 * input netdev (recorded at conn_add) and the reply-direction input netdev
 * (recorded at conn_established) for 'conn'. */
bool
ct_offload_dummy_is_bidirectional(const struct conn *conn)
{
    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e = dummy_find__(conn);
    bool bidi = e && e->netdev_fwd_in && e->netdev_rev_in;
    ovs_mutex_unlock(&dummy_mutex);
    return bidi;
}

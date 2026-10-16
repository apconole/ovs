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
#include "ovs-thread.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(ct_offload_dummy);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

COVERAGE_DEFINE(ct_offload_dummy_add);
COVERAGE_DEFINE(ct_offload_dummy_del);
COVERAGE_DEFINE(ct_offload_dummy_upd);
COVERAGE_DEFINE(ct_offload_dummy_est);

/* Per-connection state tracked by the dummy provider. */
struct ct_dummy_entry {
    struct ovs_list list_node;
    const struct conn *conn;
    struct netdev *netdev_fwd_in;       /* Input port of the original dir. */
    struct netdev *netdev_rev_in;       /* Input port of the reply dir. */
};

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

/* Returns the name of 'netdev', or "(nil)" if it is NULL.  The returned
 * pointer is only valid while 'netdev' is alive. */
static const char *
dummy_netdev_name(const struct netdev *netdev)
{
    return netdev ? netdev_get_name(netdev) : "(nil)";
}

static bool
dummy_might_offload(const struct ct_offload_ctx *ctx)
{
    /* Only connections learned on a dummy netdev can be offloaded by this
     * provider, mirroring the can_offload check of the dpif-offload-dummy
     * provider. */
    return ctx->netdev_in
           && is_dummy_netdev_class(netdev_get_class(ctx->netdev_in));
}

static void
dummy_op_add(struct ct_offload_op *op)
{
    const struct ct_offload_ctx *ctx = &op->ctx;

    ovs_assert(ctx->conn);

    if (!dummy_might_offload(ctx)) {
        op->error = EOPNOTSUPP;
        return;
    }

    struct ct_dummy_entry *e = xmalloc(sizeof *e);

    e->conn = ctx->conn;
    e->netdev_fwd_in = ctx->netdev_in;
    e->netdev_rev_in = NULL;

    ovs_mutex_lock(&dummy_mutex);
    if (dummy_find__(ctx->conn)) {
        ovs_mutex_unlock(&dummy_mutex);
        free(e);
        VLOG_WARN_RL(&rl, "conn %p added twice", ctx->conn);
        op->error = EEXIST;
        return;
    }
    ovs_list_push_back(&dummy_conns, &e->list_node);
    ovs_mutex_unlock(&dummy_mutex);

    COVERAGE_INC(ct_offload_dummy_add);
    VLOG_DBG("conn add: conn=%p fwd_in=%s", ctx->conn,
             dummy_netdev_name(ctx->netdev_in));
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
        free(e);
    }
    ovs_mutex_unlock(&dummy_mutex);

    COVERAGE_INC(ct_offload_dummy_del);
    VLOG_DBG("conn del: conn=%p", ctx->conn);
}

static void
dummy_op_est(struct ct_offload_op *op)
{
    const struct ct_offload_ctx *ctx = &op->ctx;

    ovs_assert(ctx->conn);

    ovs_mutex_lock(&dummy_mutex);
    struct ct_dummy_entry *e = dummy_find__(ctx->conn);
    struct netdev *fwd_in = e ? e->netdev_fwd_in : NULL;

    if (e && !e->netdev_rev_in) {
        e->netdev_rev_in = ctx->netdev_in;
        op->error = 0;
        COVERAGE_INC(ct_offload_dummy_est);
    }
    ovs_mutex_unlock(&dummy_mutex);

    VLOG_DBG("conn established: conn=%p fwd_in=%s rev_in=%s",
             ctx->conn, dummy_netdev_name(fwd_in),
             dummy_netdev_name(ctx->netdev_in));
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
        COVERAGE_INC(ct_offload_dummy_upd);
        op->last_used = time_msec();
    } else {
        op->last_used = 0;
    }
    VLOG_DBG("conn update: conn=%p last_used=%lld", ctx->conn,
             op->last_used);
}

static void
dummy_batch_submit(struct ct_offload_op_batch *batch)
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
        case CT_OFFLOAD_OP_EST:
            dummy_op_est(op);
            break;
        }
    }
}

/* Drops all tracked connections.  Runs when the last opener releases the
 * provider, so that no stale 'conn' pointers outlive the provider. */
static void
dummy_close(void)
{
    struct ct_dummy_entry *e;

    ovs_mutex_lock(&dummy_mutex);
    LIST_FOR_EACH_POP (e, list_node, &dummy_conns) {
        free(e);
    }
    ovs_mutex_unlock(&dummy_mutex);
}

const struct ct_offload_class ct_offload_dummy_class = {
    .name         = "dummy",
    .open         = NULL,
    .close        = dummy_close,
    .batch_submit = dummy_batch_submit,
    .might_offload = dummy_might_offload,
};

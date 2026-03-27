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

#include "conntrack.h"
#include "conntrack-private.h"
#include "ct-offload.h"
#include "dpif-offload.h"
#include "ovs-thread.h"
#include "util.h"
#include "vswitch-idl.h"

#include "openvswitch/list.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_offload);

/* Private data slot used to mark connections that have been successfully
 * offloaded.  Allocated once at module init; no destructor needed because
 * the stored value is a plain boolean cast to pointer, not heap data. */
static ct_private_id_t ct_offload_private_id = CT_PRIVATE_ID_INVALID;

/* Node in the registered-provider list. */
struct ct_offload_class_node {
    const struct ct_offload_class *class;
    struct ovs_list               list_node;
};

/* Global list of registered CT offload classes and a mutex to protect it.
 * Providers are expected to be registered at module init time and
 * unregistered only at module teardown, so contention is minimal. */
static struct ovs_mutex ct_offload_mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_list  ct_offload_classes
    OVS_GUARDED_BY(ct_offload_mutex)
    = OVS_LIST_INITIALIZER(&ct_offload_classes);

/* Built-in CT offload provider classes.  Only those whose name matches a
 * registered dpif offload class will be activated by ct_offload_module_init().
 */
static const struct ct_offload_class *base_ct_offload_classes[] = {
    /* Dummy provider: activated whenever the "dummy" dpif offload class is
     * registered (hw-offload=true with a dummy datapath).  Also used directly
     * by unit tests via ct_offload_dummy_register(). */
    &ct_offload_dummy_class,
#ifdef DPDK_NETDEV
    &ct_offload_dpdk_class,
#endif
};


/* ct_offload_register() - register a CT offload provider class.
 *
 * Calls class->init() if provided.  Returns 0 on success or a positive
 * errno value on failure.  Attempting to register the same class twice
 * returns EEXIST. */
int
ct_offload_register(const struct ct_offload_class *class)
{
    struct ct_offload_class_node *node;
    int error = 0;

    ovs_assert(class);
    ovs_assert(class->name);

    ovs_mutex_lock(&ct_offload_mutex);

    /* Detect duplicate registrations. */
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (!strcmp(node->class->name, class->name)) {
            VLOG_WARN("attempted to register duplicate ct offload class: %s",
                      class->name);
            error = EEXIST;
            goto out;
        }
    }

    error = class->init ? class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize ct offload class %s: %s",
                  class->name, ovs_strerror(error));
        goto out;
    }

    node = xmalloc(sizeof *node);
    node->class = class;
    ovs_list_push_back(&ct_offload_classes, &node->list_node);
    VLOG_DBG("registered ct offload class: %s", class->name);

out:
    ovs_mutex_unlock(&ct_offload_mutex);
    return error;
}

/* ct_offload_unregister() - unregister a previously registered class.
 *
 * Safe to call even if the class was never registered (no-op in that
 * case). */
void
ct_offload_unregister(const struct ct_offload_class *class)
{
    struct ct_offload_class_node *node;

    ovs_assert(class);

    ovs_mutex_lock(&ct_offload_mutex);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (node->class == class) {
            ovs_list_remove(&node->list_node);
            free(node);
            VLOG_DBG("unregistered ct offload class: %s", class->name);
            goto out;
        }
    }
    VLOG_WARN("attempted to unregister unknown ct offload class: %s",
              class->name);

out:
    ovs_mutex_unlock(&ct_offload_mutex);
}

/* ct_offload_module_init() - register built-in CT offload providers.
 *
 * Only registers providers whose name matches a currently-registered dpif
 * offload class, so CT offload is automatically tied to the active hardware
 * offload provider.  Safe to call multiple times; subsequent calls are
 * no-ops (duplicate registration is detected and skipped). */
void
ct_offload_module_init(void)
{
    /* Allocate the per-connection "is offloaded" private slot once. */
    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        ct_offload_private_id = conn_private_id_alloc(NULL);
        if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
            VLOG_WARN("failed to allocate ct offload private id: "
                      "is-offloaded tracking disabled");
        }
    }

    for (int i = 0; i < ARRAY_SIZE(base_ct_offload_classes); i++) {
        const struct ct_offload_class *class = base_ct_offload_classes[i];

        if (dpif_offload_class_is_registered(class->name)) {
            ct_offload_register(class);
        }
    }
}

/* ct_offload_enabled() - returns true when hardware offload is active.
 *
 * Delegates to dpif_offload_enabled() so CT offload shares the same global
 * enable/disable knob as datapath hardware offload. */
bool
ct_offload_enabled(void)
{
    return dpif_offload_enabled();
}

/* ct_offload_set_global_cfg() - configure CT offload from OVSDB.
 *
 * Must be called alongside dpif_offload_set_global_cfg() so that CT offload
 * providers are registered once hardware offload has been enabled and the
 * appropriate dpif offload classes are known. */
void
ct_offload_set_global_cfg(const struct ovsrec_open_vswitch *cfg OVS_UNUSED)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (!dpif_offload_enabled()) {
        return;
    }

    if (ovsthread_once_start(&once)) {
        ct_offload_module_init();
        ovsthread_once_done(&once);
    }
}

/* ct_offload_conn_add_() - notify all eligible providers of a new connection.
 *
 * Iterates over registered providers and calls conn_add() on each one that
 * reports can_offload() == true for this context.  Returns the first non-zero
 * error encountered, but continues notifying remaining providers.  This allows
 * the underlying hardware conntrack details across providers function.
 *
 * `locked` tells the function that the offload mutex is already acquired. */
static int
ct_offload_conn_add_(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;
    int ret = 0;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->can_offload && !class->can_offload(ctx)) {
            continue;
        }
        if (class->conn_add) {
            int error = class->conn_add(ctx);

            if (error && !ret) {
                ret = error;
            }
        }
    }

    return ret;
}

int
ct_offload_conn_add(const struct ct_offload_ctx *ctx)
{
    int ret;

    ovs_mutex_lock(&ct_offload_mutex);
    ret = ct_offload_conn_add_(ctx);
    if (!ret && ct_offload_private_id != CT_PRIVATE_ID_INVALID) {
        conn_private_set(CONST_CAST(struct conn *, ctx->conn),
                         ct_offload_private_id, (void *)1);
    }
    ovs_mutex_unlock(&ct_offload_mutex);

    return ret;
}

/* ct_offload_conn_del_() - notify all providers that a connection was removed.
 *
 * Called unconditionally on all providers so that each can clean up any
 * state it may have installed. */
static void
ct_offload_conn_del_(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->conn_del) {
            class->conn_del(ctx);
        }
    }
}

void
ct_offload_conn_del(const struct ct_offload_ctx *ctx)
{
    ovs_mutex_lock(&ct_offload_mutex);
    ct_offload_conn_del_(ctx);
    if (ct_offload_private_id != CT_PRIVATE_ID_INVALID) {
        conn_private_set(CONST_CAST(struct conn *, ctx->conn),
                         ct_offload_private_id, NULL);
    }
    ovs_mutex_unlock(&ct_offload_mutex);
}

/* ct_offload_conn_update() - query the hardware last-used timestamp.
 *
 * Iterates over providers and returns the first non-zero timestamp returned
 * by a provider's conn_update() callback.  Returns 0 if no provider
 * supplies a timestamp. */
static long long
ct_offload_conn_update_(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;
    long long last_used = 0;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->conn_update) {
            long long ts = class->conn_update(ctx);

            if (ts) {
                last_used = ts;
                break;
            }
        }
    }
    return last_used;
}

long long
ct_offload_conn_update(const struct ct_offload_ctx *ctx)
{
    long long ret;

    ovs_mutex_lock(&ct_offload_mutex);
    ret = ct_offload_conn_update_(ctx);
    ovs_mutex_unlock(&ct_offload_mutex);

    return ret;
}

/* ct_offload_can_offload() - returns true if any provider can offload ctx. */
static bool
ct_offload_can_offload_(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;
    bool result = false;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->can_offload && class->can_offload(ctx)) {
            result = true;
            break;
        }
    }

    return result;
}

bool
ct_offload_can_offload(const struct ct_offload_ctx *ctx)
{
    bool can_offload;

    ovs_mutex_lock(&ct_offload_mutex);
    can_offload = ct_offload_can_offload_(ctx);
    ovs_mutex_unlock(&ct_offload_mutex);

    return can_offload;
}

/* ct_offload_flush() - flush all offloaded connections from every provider. */
static void
ct_offload_flush_(void)
{
    struct ct_offload_class_node *node;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->flush) {
            class->flush();
        }
    }
}

void
ct_offload_flush(void)
{
    ovs_mutex_lock(&ct_offload_mutex);
    ct_offload_flush_();
    ovs_mutex_unlock(&ct_offload_mutex);
}


/* Batch API
 * =========
 *
 * The default implementation serialises each operation in the batch through
 * the individual per-connection dispatch functions above.  All provider
 * callbacks are invoked under the ct_offload_mutex, so the per-operation
 * lock/unlock overhead of the single-op path is avoided across the batch.
 */

#define CT_OFFLOAD_BATCH_INITIAL_SIZE 8

/* ct_offload_op_batch_init() - prepare an empty batch for use. */
void
ct_offload_op_batch_init(struct ct_offload_op_batch *batch)
{
    batch->ops      = NULL;
    batch->n_ops    = 0;
    batch->allocated = 0;
}

/* ct_offload_op_batch_add() - append one operation to the batch.
 *
 * The batch grows dynamically; callers need not pre-size it. */
void
ct_offload_op_batch_add(struct ct_offload_op_batch *batch,
                        enum ct_offload_op_type type,
                        const struct ct_offload_ctx *ctx)
{
    if (batch->n_ops == batch->allocated) {
        batch->allocated = batch->allocated
                           ? batch->allocated * 2
                           : CT_OFFLOAD_BATCH_INITIAL_SIZE;
        batch->ops = xrealloc(batch->ops,
                              batch->allocated * sizeof *batch->ops);
    }

    struct ct_offload_op *op = &batch->ops[batch->n_ops++];
    op->type     = type;
    op->ctx      = *ctx;
    op->error    = 0;
}

/* ct_offload_op_batch_submit() - execute every operation in the batch.
 *
 * Each op's 'error' field is set to the result of the corresponding
 * per-connection dispatch.  The mutex is held for the duration of each
 * operation; providers are invoked directly rather than through the
 * public single-op wrappers to avoid repeated lock/unlock cycles. */
void
ct_offload_op_batch_submit(struct ct_offload_op_batch *batch)
{
    struct ct_offload_op *op;

    ovs_mutex_lock(&ct_offload_mutex);
    CT_OFFLOAD_BATCH_OP_FOR_EACH (idx, op, batch) {

        switch (op->type) {
        case CT_OFFLOAD_OP_ADD:
            op->error = ct_offload_conn_add_(&op->ctx);
            if (!op->error && ct_offload_private_id != CT_PRIVATE_ID_INVALID) {
                conn_private_set(CONST_CAST(struct conn *, op->ctx.conn),
                                 ct_offload_private_id, (void *)1);
            }
            break;

        case CT_OFFLOAD_OP_DEL:
            ct_offload_conn_del_(&op->ctx);
            if (ct_offload_private_id != CT_PRIVATE_ID_INVALID) {
                conn_private_set(CONST_CAST(struct conn *, op->ctx.conn),
                                 ct_offload_private_id, NULL);
            }
            op->error = 0;
            break;

        case CT_OFFLOAD_OP_UPD: {
            long long ts = ct_offload_conn_update_(&op->ctx);

            op->error = ts ? 0 : ENODATA;
            break;
        }

        case CT_OFFLOAD_OP_POLICY:
            op->error = ct_offload_can_offload_(&op->ctx) ? 0 : EPERM;
            break;

        case CT_OFFLOAD_OP_FLUSH:
            ct_offload_flush_();
            op->error = 0;
            break;

        default:
            op->error = EINVAL;
            break;
        }
    }
    ovs_mutex_unlock(&ct_offload_mutex);
}

/* ct_offload_conn_is_offloaded() - return true if conn is currently offloaded.
 *
 * Reads the private slot set by ct_offload_conn_add() on success and cleared
 * by ct_offload_conn_del().  Returns false when the private slot could not be
 * allocated at init time. */
bool
ct_offload_conn_is_offloaded(const struct conn *conn)
{
    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        return false;
    }
    return conn_private_get(conn, ct_offload_private_id) != NULL;
}

/* ct_offload_op_batch_destroy() - release memory held by the batch.
 *
 * The batch may be re-initialised with ct_offload_op_batch_init() after
 * this call. */
void
ct_offload_op_batch_destroy(struct ct_offload_op_batch *batch)
{
    free(batch->ops);
    batch->ops       = NULL;
    batch->n_ops     = 0;
    batch->allocated = 0;
}

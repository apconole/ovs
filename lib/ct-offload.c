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

#include "ct-offload.h"

#include <errno.h>

#include "conntrack.h"
#include "conntrack-private.h"
#include "ct-offload-dummy.h"
#include "dpif-offload.h"
#include "ovs-thread.h"
#include "util.h"
#include "vswitch-idl.h"

#include "openvswitch/list.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_offload);

/* Built-in CT offload provider classes.  Only those whose name matches a
 * registered dpif offload class will be activated by ct_offload_module_init(). */
static const struct ct_offload_class *base_ct_offload_classes[] = {
    /* Dummy provider: activated whenever the "dummy" dpif offload class is
     * registered (hw-offload=true with a dummy datapath).  Also used directly
     * by unit tests via ct_offload_dummy_register(). */
    &ct_offload_dummy_class,
};

/* Private slot for storing per-connection offload state. */
static ct_private_id_t ct_offload_private_id = CT_PRIVATE_ID_INVALID;

/* Values stored in the private slot. */
#define CT_OFFLOAD_STATE_NONE  ((void *)(uintptr_t) 0)  /* Not offloaded. */
#define CT_OFFLOAD_STATE_ADDED ((void *)(uintptr_t) 1)  /* Offload pending. */
#define CT_OFFLOAD_STATE_EST   ((void *)(uintptr_t) 2)  /* Established. */

/* Node in the registered-provider list. */
struct ct_offload_class_node {
    const struct ct_offload_class *class;
    struct ovs_list               list_node;
};

/* Global list of registered CT offload classes.  Write lock is held only
 * during register/unregister; fast-path operations hold the read lock so
 * multiple PMD threads can iterate concurrently. */
static struct ovs_rwlock ct_offload_classes_rwlock = OVS_RWLOCK_INITIALIZER;
static struct ovs_list   ct_offload_classes
    OVS_GUARDED_BY(ct_offload_classes_rwlock)
    = OVS_LIST_INITIALIZER(&ct_offload_classes);


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
    ovs_assert(class->conn_add);
    ovs_assert(class->conn_del);
    ovs_assert(class->can_offload);

    ovs_rwlock_wrlock(&ct_offload_classes_rwlock);

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
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);
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

    ovs_rwlock_wrlock(&ct_offload_classes_rwlock);
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
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);
}

/* ct_offload_alloc_private_slot() - allocate the per-connection private slot.
 *
 * Called once at module init.  Logs an error if the slot pool is exhausted. */
static void
ct_offload_alloc_private_slot(void)
{
    ct_offload_private_id = conn_private_id_alloc(NULL);
    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        VLOG_ERR("failed to allocate private slot for ct offload");
    }
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
    ct_offload_alloc_private_slot();
    for (size_t i = 0; i < ARRAY_SIZE(base_ct_offload_classes); i++) {
        const struct ct_offload_class *class = base_ct_offload_classes[i];

        if (dpif_offload_class_is_registered(class->name)) {
            ct_offload_register(class);
        }
    }
}

/* ct_offload_init_for_tests() - allocate the internal private slot for tests.
 *
 * Must not be called in production code; use ct_offload_module_init()
 * instead. */
void
ct_offload_init_for_tests(void)
{
    ct_offload_alloc_private_slot();
}

/* Used only in testing to bypass the hardware-offload gate. */
static bool ct_offload_forced = false;

void
ct_offload_force_enable(bool value)
{
    ct_offload_forced = value;
}

/* ct_offload_enabled() - returns true when hardware offload is active.
 *
 * Delegates to dpif_offload_enabled() so CT offload shares the same global
 * enable/disable knob as datapath hardware offload. */
bool
ct_offload_enabled(void)
{
    return dpif_offload_enabled() || ct_offload_forced;
}

/* ct_offload_set_global_cfg() - configure CT offload from OVSDB.
 *
 * Called internally by dpif_offload_set_global_cfg() once hardware offload
 * has been enabled and the appropriate dpif offload classes are known. */
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

/* Internal helpers -- callers must hold ct_offload_classes_rwlock (rdlock).
 *
 * When 'batched' is true the helper skips providers that implement
 * batch_submit, since those were already handled by ct_offload_op_batch_submit
 * before the per-op fallback loop runs. */

/* ct_offload_conn_add__() - notify all eligible providers of a new connection.
 *
 * Iterates over registered providers and calls conn_add() on each one that
 * reports can_offload() == true for this context.  Returns the first non-zero
 * error encountered, but continues notifying remaining providers. */
static int
ct_offload_conn_add__(const struct ct_offload_ctx *ctx, bool batched)
    OVS_REQ_RDLOCK(ct_offload_classes_rwlock)
    OVS_REQUIRES(ctx->conn->lock)
{
    struct ct_offload_class_node *node;
    bool offloaded = false;
    int ret = 0;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (batched && class->batch_submit) {
            continue;
        }

        if (!class->can_offload(ctx)) {
            continue;
        }

        int error = class->conn_add(ctx);

        if (!error) {
            offloaded = true;
        } else if (!ret) {
            ret = error;
        }
    }

    if (offloaded) {
        conn_private_set(ctx->conn, ct_offload_private_id,
                         CT_OFFLOAD_STATE_ADDED);
    }

    return ret;
}

int
ct_offload_conn_add(const struct ct_offload_ctx *ctx)
    OVS_REQUIRES(ctx->conn->lock)
{
    int ret;

    ovs_rwlock_rdlock(&ct_offload_classes_rwlock);
    ret = ct_offload_conn_add__(ctx, false);
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);

    return ret;
}

/* ct_offload_conn_del__() - notify all providers that a connection was removed.
 *
 * Called unconditionally on all providers so that each can clean up any
 * state it may have installed. */
static void
ct_offload_conn_del__(const struct ct_offload_ctx *ctx, bool batched)
    OVS_REQ_RDLOCK(ct_offload_classes_rwlock)
    OVS_REQUIRES(ctx->conn->lock)
{
    struct ct_offload_class_node *node;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (batched && class->batch_submit) {
            continue;
        }

        class->conn_del(ctx);
    }

    conn_private_set(ctx->conn, ct_offload_private_id, CT_OFFLOAD_STATE_NONE);
}

void
ct_offload_conn_del(const struct ct_offload_ctx *ctx)
    OVS_REQUIRES(ctx->conn->lock)
{
    ovs_rwlock_rdlock(&ct_offload_classes_rwlock);
    ct_offload_conn_del__(ctx, false);
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);
}

static void
ct_offload_conn_established__(const struct ct_offload_ctx *ctx, bool batched)
    OVS_REQ_RDLOCK(ct_offload_classes_rwlock)
    OVS_REQUIRES(ctx->conn->lock)
{
    if (conn_private_get(ctx->conn, ct_offload_private_id)
        != CT_OFFLOAD_STATE_ADDED) {
        return;
    }

    struct ct_offload_class_node *node;
    bool established = false;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (batched && class->batch_submit) {
            continue;
        }

        if (class->conn_established && class->conn_established(ctx)) {
            established = true;
        }
    }

    if (established) {
        conn_private_set(ctx->conn, ct_offload_private_id,
                         CT_OFFLOAD_STATE_EST);
    }
}

void
ct_offload_conn_established(const struct ct_offload_ctx *ctx)
    OVS_REQUIRES(ctx->conn->lock)
{
    ovs_rwlock_rdlock(&ct_offload_classes_rwlock);
    ct_offload_conn_established__(ctx, false);
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);
}

bool
ct_offload_conn_is_offloaded(const struct conn *conn)
    OVS_REQUIRES(conn->lock)
{
    void *state = conn_private_get(conn, ct_offload_private_id);

    return state == CT_OFFLOAD_STATE_ADDED || state == CT_OFFLOAD_STATE_EST;
}

bool
ct_offload_conn_is_established(const struct conn *conn)
    OVS_REQUIRES(conn->lock)
{
    return conn_private_get(conn, ct_offload_private_id)
           == CT_OFFLOAD_STATE_EST;
}

/* ct_offload_conn_update__() - query the hardware last-used timestamp.
 *
 * Iterates over providers and returns the first non-zero timestamp returned
 * by a provider's conn_update() callback.  Returns 0 if no provider
 * supplies a timestamp. */
static long long
ct_offload_conn_update__(const struct ct_offload_ctx *ctx, bool batched)
    OVS_REQ_RDLOCK(ct_offload_classes_rwlock)
{
    struct ct_offload_class_node *node;
    long long last_used = 0;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (batched && class->batch_submit) {
            continue;
        }

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

    ovs_rwlock_rdlock(&ct_offload_classes_rwlock);
    ret = ct_offload_conn_update__(ctx, false);
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);

    return ret;
}

/* ct_offload_can_offload__() - returns true if any provider can offload ctx. */
static bool
ct_offload_can_offload__(const struct ct_offload_ctx *ctx, bool batched)
    OVS_REQ_RDLOCK(ct_offload_classes_rwlock)
{
    struct ct_offload_class_node *node;
    bool result = false;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (batched && class->batch_submit) {
            continue;
        }

        if (class->can_offload(ctx)) {
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

    ovs_rwlock_rdlock(&ct_offload_classes_rwlock);
    can_offload = ct_offload_can_offload__(ctx, false);
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);

    return can_offload;
}

/* ct_offload_flush__() - flush all offloaded connections. */
static void
ct_offload_flush__(bool batched)
    OVS_REQ_RDLOCK(ct_offload_classes_rwlock)
{
    struct ct_offload_class_node *node;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (batched && class->batch_submit) {
            continue;
        }

        if (class->flush) {
            class->flush();
        }
    }
}

/* ct_offload_flush() - flush all offloaded connections from every provider. */
void
ct_offload_flush(void)
{
    ovs_rwlock_rdlock(&ct_offload_classes_rwlock);
    ct_offload_flush__(false);
    ovs_rwlock_unlock(&ct_offload_classes_rwlock);
}


/* Batch API
 * =========
 *
 * The default implementation serialises each operation in the batch through
 * the individual per-connection dispatch functions above.  All provider
 * callbacks are invoked under the ct_offload_classes_rwlock (rdlock), so the
 * per-operation lock/unlock overhead of the single-op path is avoided across
 * the batch.
 */

#define CT_OFFLOAD_BATCH_INITIAL_SIZE 8

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

    op->type  = type;
    op->ctx   = *ctx;
    op->error = 0;
}

/* ct_offload_op_batch_submit() - execute every operation in the batch.
 *
 * Each op's 'error' field is set to the result of the corresponding
 * per-connection dispatch.  The rwlock is held for the duration of the
 * batch; providers are invoked directly rather than through the public
 * single-op wrappers to avoid repeated lock/unlock cycles. */
void
ct_offload_op_batch_submit(struct ct_offload_op_batch *batch)
{
    struct ct_offload_class_node *node;
    struct ct_offload_op *op;

    ovs_rwlock_rdlock(&ct_offload_classes_rwlock);

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->batch_submit) {
            class->batch_submit(batch);
        }
    }

    CT_OFFLOAD_BATCH_OP_FOR_EACH (idx, op, batch) {

        switch (op->type) {
        case CT_OFFLOAD_OP_ADD:
            ovs_mutex_lock(&op->ctx.conn->lock);
            op->error = ct_offload_conn_add__(&op->ctx, true);
            ovs_mutex_unlock(&op->ctx.conn->lock);
            break;

        case CT_OFFLOAD_OP_DEL:
            ovs_mutex_lock(&op->ctx.conn->lock);
            ct_offload_conn_del__(&op->ctx, true);
            ovs_mutex_unlock(&op->ctx.conn->lock);
            op->error = 0;
            break;

        case CT_OFFLOAD_OP_UPD: {
            long long ts = ct_offload_conn_update__(&op->ctx, true);

            op->error = ts ? 0 : EIO;
            break;
        }

        case CT_OFFLOAD_OP_POLICY:
            op->error = ct_offload_can_offload__(&op->ctx, true) ? 0 : EPERM;
            break;

        case CT_OFFLOAD_OP_FLUSH:
            ct_offload_flush__(true);
            op->error = 0;
            break;

        case CT_OFFLOAD_OP_EST:
            ovs_mutex_lock(&op->ctx.conn->lock);
            ct_offload_conn_established__(&op->ctx, true);
            ovs_mutex_unlock(&op->ctx.conn->lock);
            op->error = 0;
            break;

        default:
            op->error = EINVAL;
            break;
        }
    }

    ovs_rwlock_unlock(&ct_offload_classes_rwlock);
}

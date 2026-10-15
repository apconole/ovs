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

#include "ovs-thread.h"
#include "util.h"

#include "openvswitch/list.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_offload);

/* Private slot for storing per-connection offload state.  Allocated when
 * the first provider class is registered, which must happen before any
 * connections are created. */
static ct_private_id_t ct_offload_private_id = CT_PRIVATE_ID_INVALID;

/* Values stored in the private slot. */
#define CT_OFFLOAD_STATE_NONE  ((void *)(uintptr_t) 0)  /* Not offloaded. */
#define CT_OFFLOAD_STATE_ADDED ((void *)(uintptr_t) 1)  /* Offload pending. */
#define CT_OFFLOAD_STATE_EST   ((void *)(uintptr_t) 2)  /* Established. */

/* Node in the registered-provider list. */
struct ct_offload_class_node {
    const struct ct_offload_class *class;
    int refcnt;                     /* Number of open users; providers with
                                     * a zero refcnt are registered but not
                                     * active and do not see operations.
                                     * Written under the write lock, read
                                     * under the read lock. */
    struct ovs_list list_node;
};

/* Global list of registered CT offload classes and a rwlock to protect it.
 * Write lock is held only during register/unregister/open/close; fast-path
 * operations hold the read lock so multiple PMD threads can iterate
 * concurrently. */
static struct ovs_rwlock ct_offload_rwlock = OVS_RWLOCK_INITIALIZER;
static struct ovs_list ct_offload_classes
    OVS_GUARDED_BY(ct_offload_rwlock)
    = OVS_LIST_INITIALIZER(&ct_offload_classes);

/* Looks up 'name' in the registered class list.  The caller must hold
 * ct_offload_rwlock. */
static struct ct_offload_class_node *
ct_offload_class_find__(const char *name)
    OVS_REQUIRES(ct_offload_rwlock)
{
    struct ct_offload_class_node *node;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (!strcmp(node->class->name, name)) {
            return node;
        }
    }
    return NULL;
}

/* ct_offload_register() - register a CT offload provider class.
 *
 * Calls class->init() if provided.  Registration does not activate the
 * provider; the dpif-offload provider must call ct_offload_open() for
 * that.  Returns 0 on success or a positive errno value on failure.
 * Attempting to register the same class name twice returns EEXIST. */
int
ct_offload_register(const struct ct_offload_class *class)
{
    struct ct_offload_class_node *node;
    int error = 0;

    ovs_assert(class);
    ovs_assert(class->name);
    ovs_assert(class->batch_submit);
    ovs_assert(class->might_offload);

    ovs_rwlock_wrlock(&ct_offload_rwlock);

    /* Detect duplicate registrations. */
    if (ct_offload_class_find__(class->name)) {
        VLOG_WARN("attempted to register duplicate ct offload class: %s",
                  class->name);
        error = EEXIST;
        goto out;
    }

    /* The private slot must exist before any connections are created;
     * registration is documented to happen that early, so allocate on
     * first use.  The stored state is a tagged value, not allocated
     * memory, so no destructor is required. */
    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        ct_offload_private_id = conn_private_id_alloc(NULL);
    }

    error = class->init ? class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize ct offload class %s: %s",
                  class->name, ovs_strerror(error));
        goto out;
    }

    node = xmalloc(sizeof *node);
    node->class = class;
    node->refcnt = 0;
    ovs_list_push_back(&ct_offload_classes, &node->list_node);
    VLOG_DBG("registered ct offload class: %s", class->name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
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

    ovs_rwlock_wrlock(&ct_offload_rwlock);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (node->class == class) {
            if (node->refcnt > 0) {
                VLOG_WARN("unregistering still-open ct offload class: %s",
                          class->name);
            }
            ovs_list_remove(&node->list_node);
            free(node);
            VLOG_DBG("unregistered ct offload class: %s", class->name);
            goto out;
        }
    }
    VLOG_WARN("attempted to unregister unknown ct offload class: %s",
              class->name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
}

/* ct_offload_open() - activate the named provider for use.
 *
 * Called by the dpif-offload provider that owns the ports and hardware
 * resources when it needs conntrack offload from the named provider.
 * Opens are refcounted; class->open() runs on the first open.  Returns 0
 * on success or a positive errno value on failure. */
int
ct_offload_open(const char *name)
{
    struct ct_offload_class_node *node;
    int error = 0;

    ovs_rwlock_wrlock(&ct_offload_rwlock);
    node = ct_offload_class_find__(name);
    if (!node) {
        VLOG_INFO("attempted to open unknown ct offload class: %s", name);
        error = ENOENT;
        goto out;
    }

    if (node->refcnt == 0 && node->class->open) {
        error = node->class->open();
        if (error) {
            VLOG_WARN("failed to open ct offload class %s: %s",
                      name, ovs_strerror(error));
            goto out;
        }
    }
    node->refcnt++;
    VLOG_DBG("opened ct offload class: %s", name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
    return error;
}

/* ct_offload_close() - release a previously opened provider.
 *
 * Paired with an earlier successful ct_offload_open().  class->close()
 * runs when the last opener releases the provider. */
void
ct_offload_close(const char *name)
{
    struct ct_offload_class_node *node;

    ovs_rwlock_wrlock(&ct_offload_rwlock);
    node = ct_offload_class_find__(name);
    if (!node || node->refcnt == 0) {
        VLOG_WARN("attempted to close non-open ct offload class: %s", name);
        goto out;
    }

    if (--node->refcnt == 0 && node->class->close) {
        node->class->close();
    }
    VLOG_DBG("closed ct offload class: %s", name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
}

/* ct_offload_module_init() - register built-in CT offload providers.
 *
 * Must be called once before any connections are created. */
void
ct_offload_module_init(void)
{
    /* No built-in providers yet; third parties call ct_offload_register()
     * directly from their own module-init routines. */
}

/* ct_offload_op_batch_add() - append one operation to 'batch'.
 *
 * The context is copied by value; no references are taken on ctx.conn or
 * ctx.netdev_in, so they must remain valid until the batch is submitted. */
void
ct_offload_op_batch_add(struct ct_offload_op_batch *batch,
                        enum ct_offload_op_type type,
                        const struct ct_offload_ctx *ctx)
{
    if (batch->n_ops == batch->allocated) {
        batch->allocated = batch->allocated ? 2 * batch->allocated : 8;
        batch->ops = xrealloc(batch->ops,
                              batch->allocated * sizeof *batch->ops);
    }

    struct ct_offload_op *op = &batch->ops[batch->n_ops++];

    op->type = type;
    op->ctx = *ctx;
    op->error = 0;
    op->last_used = 0;
}

/* Updates the per-connection offload state from the results of 'op'.
 * Called with ct_offload_rwlock released, taking conn->lock by itself. */
static void
ct_offload_op_mark(struct ct_offload_op *op)
{
    struct conn *conn = op->ctx.conn;
    void *state;

    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        return;
    }

    ovs_mutex_lock(&conn->lock);
    state = conn_private_get(conn, ct_offload_private_id);

    switch (op->type) {
    case CT_OFFLOAD_OP_ADD:
        if (!op->error && state == CT_OFFLOAD_STATE_NONE) {
            conn_private_set(conn, ct_offload_private_id,
                             CT_OFFLOAD_STATE_ADDED);
        }
        break;
    case CT_OFFLOAD_OP_EST:
        if (!op->error && state == CT_OFFLOAD_STATE_ADDED) {
            conn_private_set(conn, ct_offload_private_id,
                             CT_OFFLOAD_STATE_EST);
        }
        break;
    case CT_OFFLOAD_OP_DEL:
        conn_private_set(conn, ct_offload_private_id, CT_OFFLOAD_STATE_NONE);
        break;
    case CT_OFFLOAD_OP_UPD:
        break;
    }
    ovs_mutex_unlock(&conn->lock);
}

/* ct_offload_op_batch_submit() - submit 'batch' to every open provider.
 *
 * Each provider's batch_submit() callback runs with only the read side of
 * ct_offload_rwlock held, in registration order, and fills in the op
 * result fields as documented with enum ct_offload_op_type.  When more
 * than one provider is open, later providers may overwrite the results of
 * earlier ones; see the notes in ct-offload.h.
 *
 * After all providers have run, the per-connection offload state is
 * updated from the op results (ADD accepted -> ADDED, EST accepted ->
 * EST, DEL -> NONE).  This happens with ct_offload_rwlock released to
 * keep the lock order strict: ct_offload_rwlock always nests outside
 * conn->lock, so code must never call into ct-offload with conn->lock
 * held.  Providers that need conn state inside batch_submit() follow the
 * same order and take conn->lock themselves. */
void
ct_offload_op_batch_submit(struct ct_offload_op_batch *batch)
{
    struct ct_offload_class_node *node;

    ovs_rwlock_rdlock(&ct_offload_rwlock);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (node->refcnt == 0) {
            continue;
        }
        node->class->batch_submit(batch);
    }
    ovs_rwlock_unlock(&ct_offload_rwlock);

    for (size_t i = 0; i < batch->n_ops; i++) {
        ct_offload_op_mark(&batch->ops[i]);
    }
}

/* ct_offload_conn_add() - submit an ADD op for 'ctx' to every open
 * provider.
 *
 * Providers that decline (EOPNOTSUPP) or fail are logged at debug level;
 * the framework does not propagate per-provider errors to the caller, as
 * remaining providers must still be notified for their hardware conntrack
 * details to function. */
void
ct_offload_conn_add(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_op op = { .type = CT_OFFLOAD_OP_ADD, .ctx = *ctx };
    struct ct_offload_op_batch batch = {
        .ops = &op, .n_ops = 1, .allocated = 1
    };

    ct_offload_op_batch_submit(&batch);

    if (op.error && op.error != EOPNOTSUPP) {
        VLOG_DBG("ct offload failed to add connection: %s",
                 ovs_strerror(op.error));
    }
}

/* ct_offload_conn_del() - submit a DEL op for 'ctx' to every open
 * provider.
 *
 * Called unconditionally so that each provider can clean up any state it
 * may have installed. */
void
ct_offload_conn_del(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_op op = { .type = CT_OFFLOAD_OP_DEL, .ctx = *ctx };
    struct ct_offload_op_batch batch = {
        .ops = &op, .n_ops = 1, .allocated = 1
    };

    ct_offload_op_batch_submit(&batch);
}

/* ct_offload_conn_update() - submit an UPD op for 'ctx'.
 *
 * Returns the hardware last-used timestamp in milliseconds since epoch,
 * or 0 if no open provider supplied one. */
long long
ct_offload_conn_update(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_op op = { .type = CT_OFFLOAD_OP_UPD, .ctx = *ctx };
    struct ct_offload_op_batch batch = {
        .ops = &op, .n_ops = 1, .allocated = 1
    };

    ct_offload_op_batch_submit(&batch);

    return op.last_used;
}

/* ct_offload_conn_established() - submit an EST op for 'ctx'.
 *
 * Returns true if the connection is fully established in hardware, false
 * if establishment failed or was deferred, or no providers are open (the
 * error field stays EBUSY in that case). */
bool
ct_offload_conn_established(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_op op = {
        .type = CT_OFFLOAD_OP_EST, .ctx = *ctx, .error = EBUSY
    };
    struct ct_offload_op_batch batch = {
        .ops = &op, .n_ops = 1, .allocated = 1
    };

    ct_offload_op_batch_submit(&batch);

    return op.error == 0;
}

/* ct_offload_might_offload() - returns true if any open provider might
 * offload 'ctx'. */
bool
ct_offload_might_offload(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;
    bool result = false;

    ovs_rwlock_rdlock(&ct_offload_rwlock);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (node->refcnt == 0) {
            continue;
        }
        if (node->class->might_offload(ctx)) {
            result = true;
            break;
        }
    }
    ovs_rwlock_unlock(&ct_offload_rwlock);

    return result;
}

/* ct_offload_conn_is_tracked() - returns true if a provider accepted the
 * connection (state ADDED or EST).  Note that this does not mean hardware
 * has confirmed the connection; use ct_offload_conn_is_established() for
 * that. */
bool
ct_offload_conn_is_tracked(const struct conn *conn)
    OVS_REQUIRES(conn->lock)
{
    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        return false;
    }

    void *state = conn_private_get(conn, ct_offload_private_id);

    return state == CT_OFFLOAD_STATE_ADDED || state == CT_OFFLOAD_STATE_EST;
}

/* ct_offload_conn_is_established() - returns true if a provider confirmed
 * the connection established in hardware (state EST). */
bool
ct_offload_conn_is_established(const struct conn *conn)
    OVS_REQUIRES(conn->lock)
{
    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        return false;
    }

    return conn_private_get(conn, ct_offload_private_id)
           == CT_OFFLOAD_STATE_EST;
}

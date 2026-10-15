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
#include "dpif-offload.h"
#include "ovs-thread.h"
#include "timeval.h"
#include "util.h"
#include "vswitch-idl.h"

#include "openvswitch/list.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_offload);

/* Built-in CT offload provider classes.  Only those whose name matches a
 * registered dpif offload class are activated by ct_offload_module_init(),
 * tying CT offload to the active hardware offload provider.  Populated as
 * concrete providers are added in later patches. */
static const struct ct_offload_class *base_ct_offload_classes[]
    OVS_UNUSED = {
};

/* Private slot for storing per-connection offload state.  Allocated when
 * the first provider class is registered, which must happen before any
 * connections are created. */
static ct_private_id_t ct_offload_private_id = CT_PRIVATE_ID_INVALID;

enum ct_offload_state {
    CT_OFFLOAD_STATE_NONE,          /* Not offloaded. */
    CT_OFFLOAD_STATE_ADDED,         /* Offload pending. */
    CT_OFFLOAD_STATE_EST            /* Established. */
};

/* Per-connection offload data stored in the private slot; NULL (the
 * initial slot value) means never offloaded.  The state member is written
 * under conn->lock; last_extend_ts is initialized when the connection is
 * established and afterwards only touched by the expiration sweeper,
 * which runs under ct_lock. */
struct ct_offload_data {
    enum ct_offload_state state;
    long long last_extend_ts;       /* Last hardware timestamp used to
                                     * extend the connection's expiration. */
};

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
     * first use.  Per-connection data is heap allocated, so the slot is
     * registered with free() as its destructor. */
    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        ct_offload_private_id = conn_private_id_alloc(free);
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
 * Only registers providers whose name matches a currently-registered dpif
 * offload class, so CT offload is automatically tied to the active
 * hardware offload provider.  Safe to call multiple times; subsequent
 * calls are no-ops (duplicate registration is detected and skipped). */
void
ct_offload_module_init(void)
{
    size_t n_classes = ARRAY_SIZE(base_ct_offload_classes);

    for (size_t i = 0; i < n_classes; i++) {
        const struct ct_offload_class *class = base_ct_offload_classes[i];

        if (!dpif_offload_class_is_registered(class->name)) {
            continue;
        }

        int error = ct_offload_register(class);
        if (error && error != EEXIST) {
            VLOG_WARN("failed to register ct offload class %s: %s",
                      class->name, ovs_strerror(error));
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
    struct ct_offload_data *data;

    if (ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        return;
    }

    ovs_mutex_lock(&conn->lock);
    data = conn_private_get(conn, ct_offload_private_id);

    switch (op->type) {
    case CT_OFFLOAD_OP_ADD:
        if (!op->error && !data) {
            data = xzalloc(sizeof *data);
            data->state = CT_OFFLOAD_STATE_ADDED;
            conn_private_set(conn, ct_offload_private_id, data);
        }
        break;
    case CT_OFFLOAD_OP_EST:
        if (!op->error && data
            && data->state == CT_OFFLOAD_STATE_ADDED) {
            data->state = CT_OFFLOAD_STATE_EST;
            /* Baseline for expiration sliding: hardware activity at or
             * after this point advances the deadline. */
            data->last_extend_ts = time_msec();
        }
        break;
    case CT_OFFLOAD_OP_DEL:
        conn_private_set(conn, ct_offload_private_id, NULL);
        free(data);
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
 * Called unconditionally on connection deletion; the tracked check is
 * performed internally so that providers are not disturbed for connections
 * that were never offloaded. */
void
ct_offload_conn_del(const struct ct_offload_ctx *ctx)
{
    bool tracked;

    ovs_mutex_lock(&ctx->conn->lock);
    tracked = ct_offload_conn_is_tracked(ctx->conn);
    ovs_mutex_unlock(&ctx->conn->lock);

    if (!tracked) {
        return;
    }

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
 * The transition is only meaningful for connections a provider already
 * accepted, so the tracked check is performed internally.  Returns true
 * if the connection is fully established in hardware, false if
 * establishment failed or was deferred, or no providers are open (the
 * error field stays EBUSY in that case). */
bool
ct_offload_conn_established(const struct ct_offload_ctx *ctx)
{
    bool pending;

    ovs_mutex_lock(&ctx->conn->lock);
    pending = ct_offload_conn_is_tracked(ctx->conn)
              && !ct_offload_conn_is_established(ctx->conn);
    ovs_mutex_unlock(&ctx->conn->lock);

    if (!pending) {
        return false;
    }

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

    return conn_private_get(conn, ct_offload_private_id) != NULL;
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

    struct ct_offload_data *data =
        conn_private_get(conn, ct_offload_private_id);

    return data && data->state == CT_OFFLOAD_STATE_EST;
}

/* ct_offload_conn_extend() - slide 'conn''s expiration to account for
 * hardware activity.
 *
 * Used by the conntrack expiration sweeper after a connection has expired
 * in software but is still established in hardware.  'op' carries the
 * result of a CT_OFFLOAD_OP_UPD query; 'now' is the sweeper's current
 * time.
 *
 * The connection's existing expiration encodes its policy timeout applied
 * to the last activity seen in software.  Rather than blindly extending by
 * one sweep interval, which would keep stale connections alive forever,
 * the deadline is slid only by how much newer the hardware's last-used
 * timestamp is than the timestamp used at the previous extension:
 * hardware traffic advances the deadline, and a frozen (or missing)
 * timestamp lets the connection expire normally.  Returns true if the
 * expiration was extended past 'now'. */
bool
ct_offload_conn_extend(struct conn *conn, const struct ct_offload_op *op,
                       long long now)
{
    struct ct_offload_data *data;
    long long new_exp;

    if (op->error || !op->last_used
        || ct_offload_private_id == CT_PRIVATE_ID_INVALID) {
        return false;
    }

    data = conn_private_get(conn, ct_offload_private_id);
    if (!data) {
        return false;
    }

    long long base = data->last_extend_ts ? data->last_extend_ts : now;

    if (op->last_used <= base) {
        /* No hardware activity newer than what was already accounted for. */
        return false;
    }

    long long cur;
    atomic_read_relaxed(&conn->expiration, &cur);

    new_exp = cur + (op->last_used - base);
    data->last_extend_ts = op->last_used;

    if (new_exp <= now) {
        return false;
    }

    if (new_exp > cur) {
        atomic_store_relaxed(&conn->expiration, new_exp);
    }

    return true;
}

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

#ifndef CT_OFFLOAD_H
#define CT_OFFLOAD_H

#include "conntrack.h"
#include "conntrack-private.h"
#include "openvswitch/types.h"

struct netdev;

/* Context for offload as part of the callbacks that all connection
 * offload APIs receive.  The direction identifies which of the
 * connection's keys is the packet's match key; providers holding
 * conn->lock can derive either direction's key via
 * conn->key_node[dir].key. */
struct ct_offload_ctx {
    struct conn *conn;              /* Connection object being offloaded. */
    struct netdev *netdev_in;       /* Input netdev (may be NULL). */
    odp_port_t input_port_id;       /* ODP port number. */
    enum key_dir dir;               /* Direction of 'conn' relative to the
                                     * packet that triggered the op. */
};

/* Operations delivered to a provider's batch_submit() callback.  Each op
 * carries its own 'ctx'; the fields each type uses are noted below.  The
 * provider fills in the op result fields ('error', 'last_used'):
 *
 *   CT_OFFLOAD_OP_ADD (uses conn, netdev_in, input_port_id, dir):
 *       Attempts to offload the connection.  On success, the provider is
 *       expected to eventually install the necessary hardware state.
 *       Sets op->error to 0 if accepted, EOPNOTSUPP if this provider does
 *       not handle the connection, or another positive errno on failure.
 *
 *   CT_OFFLOAD_OP_DEL (uses conn, dir):
 *       Removes any offloaded state for the connection.  Delivered even
 *       if the ADD op was declined or never issued; providers must
 *       tolerate unknown connections.  Sets op->error to 0.
 *
 *   CT_OFFLOAD_OP_UPD (uses conn, dir):
 *       Queries hardware for the last-used time of an offloaded
 *       connection.  Sets op->last_used to the last-used time in
 *       milliseconds since epoch, or 0 if the connection is not
 *       offloaded in this provider or no timestamp is available.
 *       Sets op->error to 0.
 *
 *   CT_OFFLOAD_OP_EST (uses conn, input_port_id, dir):
 *       Notifies that the first reply-direction packet was seen, which
 *       identifies the reverse-direction input port.  Sets op->error to
 *       0 once the connection is fully established in hardware, or EBUSY
 *       if establishment failed or was deferred; a later op will be
 *       delivered on the next eligible reply packet while it keeps
 *       returning EBUSY. */
enum ct_offload_op_type {
    CT_OFFLOAD_OP_ADD,              /* Add operation. */
    CT_OFFLOAD_OP_DEL,              /* Del operation. */
    CT_OFFLOAD_OP_UPD,              /* Update (timestamp) operation. */
    CT_OFFLOAD_OP_EST,              /* Established - reply packet seen. */
};

/* A single offload operation.  The 'ctx' is embedded by value, but no
 * references are taken on ctx.conn or ctx.netdev_in; those pointers must
 * remain valid until ct_offload_op_batch_submit() returns. */
struct ct_offload_op {
    enum ct_offload_op_type type;
    struct ct_offload_ctx ctx;

    /* Result fields, filled in by the provider as documented with
     * enum ct_offload_op_type.  Initialized to 0 by the framework before
     * the batch is submitted. */
    int error;
    long long last_used;
};

/* Batched set of offload operations. */
struct ct_offload_op_batch {
    struct ct_offload_op *ops;
    size_t n_ops;
    size_t allocated;
};

#define CT_OFFLOAD_BATCH_OP_FOR_EACH(BATCH, IDX, OP)                  \
    for (size_t IDX = 0;                                              \
         (IDX) < (BATCH)->n_ops && ((OP) = &(BATCH)->ops[IDX], true); \
         (IDX)++)

static inline void
ct_offload_op_batch_init(struct ct_offload_op_batch *batch)
{
    batch->ops = NULL;
    batch->n_ops = 0;
    batch->allocated = 0;
}

static inline void
ct_offload_op_batch_destroy(struct ct_offload_op_batch *batch)
{
    free(batch->ops);
    ct_offload_op_batch_init(batch);
}

static inline size_t
ct_offload_op_batch_len(const struct ct_offload_op_batch *batch)
{
    return batch->n_ops;
}

void ct_offload_op_batch_add(struct ct_offload_op_batch *,
                             enum ct_offload_op_type type,
                             const struct ct_offload_ctx *);
void ct_offload_op_batch_submit(struct ct_offload_op_batch *);

/* CT offload class describes a conntrack offload provider implementation.
 *
 * Providers are registered globally at module initialization time, but they
 * only become active once the dpif-offload provider that owns the ports and
 * hardware resources opens them through ct_offload_open().  This mirrors the
 * init/open/close split of struct dpif_offload_class: registration makes the
 * class known to the framework, while open()/close() control actual use.
 * A single ct_offload class may be opened by more than one offload provider;
 * opens are refcounted, and close() runs when the last user releases it. */
struct ct_offload_class {
    /* Unique provider name, e.g., "dummy".  Uniqueness is checked at
     * registration time. */
    const char *name;

    /* Optional global initialization called when the class is registered.
     * This must not allocate per-port or per-instance hardware resources;
     * that belongs in open() below.  Returns 0 on success or a positive
     * errno value to abort registration.  May be NULL. */
    int (*init)(void);

    /* Activates the provider for actual use, called by the dpif-offload
     * provider through ct_offload_open() when it needs conntrack offload.
     * Returns 0 on success or a positive errno value.  May be NULL if no
     * activation work is required. */
    int (*open)(void);

    /* Deactivates the provider, called by the dpif-offload provider through
     * ct_offload_close() when it no longer needs conntrack offload.  Runs
     * when the last opener releases the provider.  Must undo whatever
     * open() did.  May be NULL if open() is NULL. */
    void (*close)(void);

    /* Submits 'batch' to the provider for execution.  This is the only
     * per-connection entry point; single operations are delivered as a
     * batch of one.  The provider must examine each op's type, perform
     * the operation (or decline it), and fill in the op's result fields
     * as documented with enum ct_offload_op_type.  Operations within a
     * batch are independent: a failure on one op must not prevent the
     * provider from processing the rest.
     *
     * The framework holds only ct_offload_rwlock (read side) across this
     * call; it does not hold any conn->lock.  A provider that accesses
     * conn state, such as conn->private[], must acquire conn->lock
     * itself.  Because the read lock is held, batch_submit() must not
     * block for extended periods.  Mandatory (non-NULL). */
    void (*batch_submit)(struct ct_offload_op_batch *batch);

    /* Checks whether this provider might offload the connection described
     * by 'ctx'.  The decision is advisory: at this point the provider may
     * not know all the details it needs (for example, the egress interface
     * is not yet known), so it may still decline the connection later in
     * a CT_OFFLOAD_OP_ADD op.  Providers should return false only when
     * they are sure they will never handle this connection.  Mandatory
     * (non-NULL). */
    bool (*might_offload)(const struct ct_offload_ctx *);
};

/* Register/unregister a provider class.  Must be called at module init,
 * before any connections are created; registration alone does not activate
 * the provider.  batch_submit and might_offload must be non-NULL. */
int  ct_offload_register(const struct ct_offload_class *);
void ct_offload_unregister(const struct ct_offload_class *);

/* Opens/closes the named ct offload provider for actual use.  Called by
 * the dpif-offload provider that owns the ports and hardware resources,
 * not by the ct offload provider itself.  Opens are refcounted, so
 * ct_offload_close() must be paired with an earlier successful
 * ct_offload_open().  Returns 0 on success or a positive errno value. */
int  ct_offload_open(const char *name);
void ct_offload_close(const char *name);

/* Module initialization (register built-in providers).  Must run before
 * any connections are created, as it allocates the per-connection private
 * slot used to track offload state. */
void ct_offload_module_init(void);


/* Returns true when CT offload is enabled (delegates to
 * dpif_offload_enabled()). */
bool ct_offload_enabled(void);

/* Offload state of a connection, tracked by the framework in a
 * conn-private slot and updated from ct_offload_op_batch_submit(): never
 * offloaded or removed, added (a provider accepted the ADD op; hardware
 * flow may not be installed yet), or established (a provider confirmed
 * establishment in hardware).
 *
 * Both helpers require conn->lock and tolerate providers never having
 * been registered. */
bool ct_offload_conn_is_tracked(const struct conn *);
bool ct_offload_conn_is_established(const struct conn *);

/* ct_offload_conn_extend() - slide 'conn''s expiration to account for
 * hardware activity reported in 'op' (the result of a CT_OFFLOAD_OP_UPD).
 *
 * The deadline is advanced only by how much newer the hardware last-used
 * timestamp is than the one accounted for at the previous extension, so
 * stale hardware entries expire normally instead of being extended every
 * sweep forever.  'now' is the current time.  Intended for the conntrack
 * expiration sweeper; returns true if the expiration was extended past
 * 'now'. */
bool ct_offload_conn_extend(struct conn *, const struct ct_offload_op *op,
                            long long now);

/* Single-operation convenience wrappers around ct_offload_op_batch_*(),
 * each submitting a batch of one op to every open provider.
 *
 * When more than one provider is open, the result reflects the last
 * provider that ran (registration order); deployments with multiple
 * concurrent providers requiring per-provider results should build an
 * explicit batch instead.
 *
 * Callers must not hold conn->lock; see the locking notes in ct-offload.c. */
void      ct_offload_conn_add(const struct ct_offload_ctx *);

/* Submits a DEL op unless the connection was never offloaded; the
 * tracked check is performed internally. */
void      ct_offload_conn_del(const struct ct_offload_ctx *);

/* Returns the hardware last-used timestamp in milliseconds since epoch,
 * or 0 if no open provider supplied one. */
long long ct_offload_conn_update(const struct ct_offload_ctx *);

/* Notifies providers of the established transition.  Returns true if the
 * connection is fully established in hardware, false if establishment
 * failed or was deferred, or no providers are open. */
bool      ct_offload_conn_established(const struct ct_offload_ctx *);
bool      ct_offload_might_offload(const struct ct_offload_ctx *);

#endif /* CT_OFFLOAD_H */

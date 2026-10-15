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
#include "openvswitch/types.h"

struct conn;
struct match;
struct nlattr;
struct netdev;

/* Context for flow-level ct offload eligibility, queried at flow-put
 * time (before any connection exists).  'ct_action' holds the nested
 * OVS_CT_ATTR_* attributes of the ct() action being installed. */
struct ct_offload_flow_ctx {
    struct netdev *netdev_in;
    const struct match *match;
    const struct nlattr *ct_action;
};

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
 * provider fills in the op result fields ('error', 'last_used',
 * 'hw_confirmed').  At most one provider handles a given connection --
 * the one whose ports the connection flows through; every other
 * provider leaves the result fields untouched:
 *
 *   CT_OFFLOAD_OP_ADD (uses conn, netdev_in, input_port_id, dir):
 *       Sets op->error to 0 if accepted, another positive errno on
 *       failure, and op->hw_confirmed if the entry is fully programmed
 *       at add time; leave the result fields untouched when not
 *       handling the connection.
 *
 *   CT_OFFLOAD_OP_DEL (uses conn, dir):
 *       Removes any offloaded state; providers must tolerate unknown
 *       connections.  Sets op->error to 0.
 *
 *   CT_OFFLOAD_OP_UPD (uses conn, dir):
 *       Sets op->last_used to the hardware last-used time in ms since
 *       epoch (0 if none).  Sets op->error to 0.  May set
 *       op->hw_confirmed if the provider noticed the connection active
 *       on its own.  Leave the result fields untouched when not
 *       holding the connection.
 *
 *   CT_OFFLOAD_OP_ESTABLISHED (uses conn, input_port_id, dir):
 *       Software observed the connection transition to established
 *       (reply-direction packet); carries the reverse-direction input
 *       port.  A signal only: providers may act on it or ignore it;
 *       it requests nothing.  A provider confirming an entry in
 *       hardware does so via op->hw_confirmed, which it may set on any
 *       op it handles.  op->error may report a failure acting on the
 *       signal (diagnostics only).  Leave the result fields untouched
 *       otherwise. */
enum ct_offload_op_type {
    CT_OFFLOAD_OP_ADD,              /* Add operation. */
    CT_OFFLOAD_OP_DEL,              /* Del operation. */
    CT_OFFLOAD_OP_UPD,              /* Update (timestamp) operation. */
    CT_OFFLOAD_OP_ESTABLISHED,      /* SW observed the established
                                     * transition. */
};

/* A single offload operation.  The 'ctx' is embedded by value, but no
 * references are taken on ctx.conn or ctx.netdev_in; those pointers must
 * remain valid until ct_offload_op_batch_submit() returns. */
struct ct_offload_op {
    enum ct_offload_op_type type;
    struct ct_offload_ctx ctx;

    /* Result fields, filled in by the provider as documented above. */
    int error;
    long long last_used;
    bool hw_confirmed;              /* Provider acknowledged the entry
                                     * in hardware. */
};

/* Ops embedded directly in struct ct_offload_op_batch; larger batches
 * fall back to a heap array. */
enum { CT_OFFLOAD_OP_BATCH_INLINE = 8 };

/* Batched set of offload operations. */
struct ct_offload_op_batch {
    struct ct_offload_op *ops;
    size_t n_ops;
    size_t allocated;
    struct ct_offload_op inline_ops[CT_OFFLOAD_OP_BATCH_INLINE];
};

#define CT_OFFLOAD_BATCH_OP_FOR_EACH(BATCH, IDX, OP)                  \
    for (size_t IDX = 0;                                              \
         (IDX) < (BATCH)->n_ops && ((OP) = &(BATCH)->ops[IDX], true); \
         (IDX)++)

static inline void
ct_offload_op_batch_init(struct ct_offload_op_batch *batch)
{
    batch->ops = batch->inline_ops;
    batch->n_ops = 0;
    batch->allocated = CT_OFFLOAD_OP_BATCH_INLINE;
}

static inline void
ct_offload_op_batch_destroy(struct ct_offload_op_batch *batch)
{
    if (batch->ops != batch->inline_ops) {
        free(batch->ops);
    }
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
 * Providers register globally at module init and become active when
 * opened through ct_offload_open() (mirroring the init/open/close split
 * of struct dpif_offload_class).  Opens are refcounted; close() runs
 * when the last user releases it. */
struct ct_offload_class {
    /* Unique provider name, e.g. "dummy". */
    const char *name;

    /* Optional; called at registration.  Per-port or per-instance
     * hardware resources belong in open().  Returns 0 or a positive
     * errno to abort registration. */
    int (*init)(void);

    /* Called by ct_offload_open() on the first open.  Returns 0 or
     * errno.  May be NULL. */
    int (*open)(void);

    /* Called by ct_offload_close() on the last release; must undo
     * open().  May be NULL if open() is. */
    void (*close)(void);

    /* Processes the ops in 'batch'; the only per-connection entry
     * point.  Fill in each op's result fields per enum
     * ct_offload_op_type; ops in a batch are independent.  Called with
     * only ct_offload_rwlock (read side) held -- no conn->lock -- and
     * must not block for extended periods; take conn->lock yourself to
     * access conn state.  Mandatory. */
    void (*batch_submit)(const struct ct_offload_op_batch *batch);

    /* May a flow containing the ct() action 'ct_action' with flow key
     * 'match' on this input netdev be fully offloaded?  Called at
     * flow-put time through ct_offload_flow_offloadable(); there is no
     * connection yet.  Providers parse only the attributes they care
     * about (commit, NAT configuration, protocol, helper, zone, ...).
     * Mandatory. */
    bool (*flow_might_offload)(const struct ct_offload_flow_ctx *);
};

/* Register/unregister a provider class.  Must be called at module init,
 * before any connections are created; registration alone does not activate
 * the provider.  batch_submit and flow_might_offload must be non-NULL. */
int  ct_offload_register(const struct ct_offload_class *);
void ct_offload_unregister(const struct ct_offload_class *);

/* Activate/deactivate a provider by name.  Refcounted; pair close()
 * with a successful open().  Returns 0 on success or a positive errno. */
int  ct_offload_open(const char *name);
void ct_offload_close(const char *name);

/* Module initialization (register built-in providers).  Must run before
 * any connections are created, as it allocates the per-connection private
 * slot used to track offload state. */
void ct_offload_module_init(void);

/* Offload state of a connection, tracked in a conn-private slot:
 * tracked (a provider accepted the ADD op) or hw-confirmed (a provider
 * acknowledged the entry in hardware).  Both require conn->lock. */
bool ct_offload_conn_is_tracked(const struct conn *);
bool ct_offload_conn_is_hw_confirmed(const struct conn *);

/* Single-operation convenience wrappers around ct_offload_op_batch_*(),
 * each submitting a batch of one op to every open provider.  Callers
 * must not hold conn->lock; see the locking notes in ct-offload.c. */
void      ct_offload_conn_add(const struct ct_offload_ctx *);
void      ct_offload_conn_del(const struct ct_offload_ctx *);

/* Returns the hardware last-used time in ms since epoch, or 0. */
long long ct_offload_conn_update(const struct ct_offload_ctx *);

/* Notifies providers of the established transition (reply-direction
 * packet); a signal only. */
void       ct_offload_conn_notify_established(const struct ct_offload_ctx *);

/* May a flow containing the ct() action 'ct_action' with flow key
 * 'match' on 'netdev_in' be fully offloaded?  Returns true if any open
 * provider claims it.  Called by dpif offload providers at flow-put
 * time; there is no connection yet. */
bool ct_offload_flow_offloadable(struct netdev *netdev_in,
                                 const struct match *match,
                                 const struct nlattr *ct_action);

#endif /* CT_OFFLOAD_H */

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

#include "openvswitch/types.h"

struct conn;
struct netdev;

/* Context for offload as part of the callbacks that all connection
 * offload APIs receive.
 */
struct ct_offload_ctx {
    const struct conn *conn;        /* Connection object being offloaded. */
    struct netdev *netdev_in;       /* Input netdev. */
    struct netdev *netdev_out;      /* (optional) Output netdev.  This may not
                                     * be populated. */
    odp_port_t input_port_id;       /* ODP port number. */
};

enum ct_offload_op_type {
    CT_OFFLOAD_OP_ADD,              /* Add operation. */
    CT_OFFLOAD_OP_DEL,              /* Del operation. */
    CT_OFFLOAD_OP_UPD,              /* Update operation. */
    CT_OFFLOAD_OP_POLICY,           /* Policy check operation. */
    CT_OFFLOAD_OP_FLUSH,            /* Flush. */
};

struct ct_offload_op {
    enum ct_offload_op_type type;
    struct ct_offload_ctx   ctx;
    int                     error;
};

/* Batched set of offload contexts and operations.*/
struct ct_offload_op_batch {
    struct ct_offload_op *ops;
    size_t                n_ops;
    size_t                allocated;
};


/* CT Offload Class — describes a conntrack offload provider implementation.
 */
struct ct_offload_class {
    const char *name;

    /* Initialization routine for the provider. */
    int (*init)(void);

    /* Per-connection operation callbacks — called for individual operations
     * on the fast path or when batching is not in use. */
    int  (*conn_add)(const struct ct_offload_ctx *);
    void (*conn_del)(const struct ct_offload_ctx *);
    /* Populate the last-used timestamp for the connection.  Returns the
     * last-used time in milliseconds since epoch, or 0 on failure. */
    long long (*conn_update)(const struct ct_offload_ctx *);
    /* Check whether this provider can offload a connection. */
    bool (*can_offload)(const struct ct_offload_ctx *);
    /* Flush all offloaded connections. */
    void (*flush)(void);
};

/* Register/unregister a provider.  Must be called at module init, before
 * any connections are created. */
int  ct_offload_register(const struct ct_offload_class *);
void ct_offload_unregister(const struct ct_offload_class *);

/* Module initialization — registers built-in providers. */
void ct_offload_module_init(void);

/* Per-connection offload API — dispatches to all registered providers. */
int       ct_offload_conn_add(const struct ct_offload_ctx *);
void      ct_offload_conn_del(const struct ct_offload_ctx *);
long long ct_offload_conn_update(const struct ct_offload_ctx *);
bool      ct_offload_can_offload(const struct ct_offload_ctx *);
void      ct_offload_flush(void);

/* Batch offload API.
 *
 * The default implementation dispatches each operation individually using the
 * per-connection API above.  Providers that can handle a native batch may do
 * so by implementing a batch_submit callback in struct ct_offload_class in the
 * future.
 *
 * Typical usage:
 *
 *   struct ct_offload_op_batch batch;
 *   ct_offload_op_batch_init(&batch);
 *
 *   ct_offload_op_batch_add(&batch, CT_OFFLOAD_OP_ADD, &ctx_a);
 *   ct_offload_op_batch_add(&batch, CT_OFFLOAD_OP_ADD, &ctx_b);
 *
 *   ct_offload_op_batch_submit(&batch);
 *   for_each_op inspect batch.ops[i].error
 *
 *   ct_offload_op_batch_destroy(&batch);
 *
 * For CT_OFFLOAD_OP_UPD, op->error is set to 0 when the hardware returned a
 * valid last-used timestamp (expiration was refreshed by the provider), or to
 * ENODATA when no hardware record was found.
 *
 * For CT_OFFLOAD_OP_POLICY, op->error is set to 0 when the connection is
 * eligible for offload, or EPERM when no provider will accept it.
 */
void ct_offload_op_batch_init(struct ct_offload_op_batch *);
void ct_offload_op_batch_add(struct ct_offload_op_batch *,
                             enum ct_offload_op_type,
                             const struct ct_offload_ctx *);
void ct_offload_op_batch_submit(struct ct_offload_op_batch *);
void ct_offload_op_batch_destroy(struct ct_offload_op_batch *);

static inline
size_t ct_offload_op_batch_len(struct ct_offload_op_batch *batch)
{
    return batch->n_ops;
}

static inline
size_t ct_offload_op_batch_size(struct ct_offload_op_batch *batch)
{
    return batch->allocated;
}

#define CT_OFFLOAD_BATCH_OP_FOR_EACH(IDX, OP, BATCH) \
    for (size_t IDX = 0; IDX < ct_offload_op_batch_len(BATCH); IDX++) \
        if (OP = &((BATCH)->ops[IDX]), true)

#endif /* CT_OFFLOAD_H */

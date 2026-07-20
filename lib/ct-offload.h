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
 * offload APIs receive.
 */
struct ct_offload_ctx {
    struct conn *conn;              /* Connection object being offloaded. */
    struct netdev *netdev_in;       /* Input netdev (NULL at conn_del/update). */
    odp_port_t input_port_id;       /* ODP port number. */
    const struct conn_key *key;     /* Forward-direction 5-tuple.  Always set. */
};

/* CT offload class describes a conntrack offload provider implementation. */
struct ct_offload_class {
    const char *name;

    /* Optional initialization routine for the provider. */
    int (*init)(void);

    /* Per-connection operation callbacks get called for individual operations
     * on the fast path or when batching is not in use.
     * conn_add, conn_del, and can_offload are mandatory (non-NULL). */
    int  (*conn_add)(const struct ct_offload_ctx *);
    void (*conn_del)(const struct ct_offload_ctx *);

    /* Populate the last-used timestamp for the connection.  Returns the
     * last-used time in milliseconds since epoch, or 0 if the connection
     * is not offloaded or the timestamp is not available.  The caller only
     * updates the connection expiration if the returned value is newer than
     * the current expiration. */
    long long (*conn_update)(const struct ct_offload_ctx *);
    /* Called exactly once when the first reply-direction packet is seen
     * for an offloaded connection. */
    void (*conn_established)(const struct ct_offload_ctx *);
    /* Check whether this provider can offload a connection. */
    bool (*can_offload)(const struct ct_offload_ctx *);
    /* Flush all offloaded connections. */
    void (*flush)(void);
};

/* Register/unregister a provider.  Must be called at module init, before
 * any connections are created.  conn_add, conn_del, and can_offload must
 * be non-NULL. */
int  ct_offload_register(const struct ct_offload_class *);
void ct_offload_unregister(const struct ct_offload_class *);

/* Module initialization (register built-in providers). */
void ct_offload_module_init(void);

/* Per-connection offload API that dispatches to all registered providers. */
int       ct_offload_conn_add(const struct ct_offload_ctx *);
void      ct_offload_conn_del(const struct ct_offload_ctx *);
long long ct_offload_conn_update(const struct ct_offload_ctx *);
void      ct_offload_conn_established(const struct ct_offload_ctx *);
bool      ct_offload_can_offload(const struct ct_offload_ctx *);
void      ct_offload_flush(void);

#endif /* CT_OFFLOAD_H */

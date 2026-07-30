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
 * offload APIs receive. */
struct ct_offload_ctx {
    struct conn *conn;              /* Connection object being offloaded. */
    struct netdev *netdev_in;       /* Input netdev (may be NULL). */
    odp_port_t input_port_id;       /* ODP port number. */
    const struct conn_key *key;     /* Forward-direction 5-tuple. */
};

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

    /* The per-connection callbacks below are called for individual
     * operations, or from batch_submit() when a provider batches.  They
     * are only called while the provider is open.  All are mandatory
     * (non-NULL) unless noted otherwise. */

    /* Attempts to offload the connection described by 'ctx'.  Called after
     * might_offload() returned true for the same context.  Returns 0 on
     * success or a positive errno value; on success the provider is
     * expected to eventually install the necessary hardware state. */
    int  (*conn_add)(const struct ct_offload_ctx *);

    /* Removes any offloaded state for the connection described by 'ctx'.
     * Called unconditionally when a connection is deleted, even if
     * conn_add() was never called or failed; providers must tolerate
     * unknown connections. */
    void (*conn_del)(const struct ct_offload_ctx *);

    /* Queries hardware for the last-used time of an offloaded connection.
     * Returns the last-used time in milliseconds since epoch, or 0 if the
     * connection is not offloaded in this provider or the timestamp is not
     * available. */
    long long (*conn_update)(const struct ct_offload_ctx *);

    /* Called when the first reply-direction packet is seen for an
     * offloaded connection, which identifies the reverse-direction input
     * port.  Returns true once the connection is fully established in
     * hardware, false if establishment failed or was deferred; a later
     * call will be made on the next eligible reply packet while it keeps
     * returning false. */
    bool (*conn_established)(const struct ct_offload_ctx *);

    /* Checks whether this provider might offload the connection described
     * by 'ctx'.  The decision is advisory: at this point the provider may
     * not know all the details it needs (for example, the egress interface
     * is not yet known), so it may still decline the connection later in
     * conn_add().  Providers should return false only when they are sure
     * they will never handle this connection. */
    bool (*might_offload)(const struct ct_offload_ctx *);
};

/* Register/unregister a provider class.  Must be called at module init,
 * before any connections are created; registration alone does not activate
 * the provider.  conn_add, conn_del, conn_update, conn_established, and
 * might_offload must be non-NULL. */
int  ct_offload_register(const struct ct_offload_class *);
void ct_offload_unregister(const struct ct_offload_class *);

/* Opens/closes the named ct offload provider for actual use.  Called by
 * the dpif-offload provider that owns the ports and hardware resources,
 * not by the ct offload provider itself.  Opens are refcounted, so
 * ct_offload_close() must be paired with an earlier successful
 * ct_offload_open().  Returns 0 on success or a positive errno value. */
int  ct_offload_open(const char *name);
void ct_offload_close(const char *name);

/* Module initialization (register built-in providers). */
void ct_offload_module_init(void);

/* Per-connection offload API that dispatches to all open providers.
 *
 * Callers must not hold conn->lock; see the locking notes in ct-offload.c. */
void      ct_offload_conn_add(const struct ct_offload_ctx *);
void      ct_offload_conn_del(const struct ct_offload_ctx *);
long long ct_offload_conn_update(const struct ct_offload_ctx *);

/* Notifies providers of the established transition.  Returns true only if
 * every open provider reports the connection fully established in
 * hardware; false if any provider deferred or failed, or none are open. */
bool      ct_offload_conn_established(const struct ct_offload_ctx *);
bool      ct_offload_might_offload(const struct ct_offload_ctx *);

#endif /* CT_OFFLOAD_H */

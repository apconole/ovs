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
 * the provider.  flow_might_offload must be non-NULL. */
int  ct_offload_register(const struct ct_offload_class *);
void ct_offload_unregister(const struct ct_offload_class *);

/* Activate/deactivate a provider by name.  Refcounted; pair close()
 * with a successful open().  Returns 0 on success or a positive errno. */
int  ct_offload_open(const char *name);
void ct_offload_close(const char *name);

/* Module initialization (register built-in providers). */
void ct_offload_module_init(void);

/* May a flow containing the ct() action 'ct_action' with flow key
 * 'match' on 'netdev_in' be fully offloaded?  Returns true if any open
 * provider claims it.  Called by dpif offload providers at flow-put
 * time; there is no connection yet. */
bool ct_offload_flow_offloadable(struct netdev *netdev_in,
                                 const struct match *match,
                                 const struct nlattr *ct_action);

#endif /* CT_OFFLOAD_H */

/*
 * Copyright (c) 2010, 2011, 2014 Nicira, Inc.
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

#ifndef DPIF_NETLINK_H
#define DPIF_NETLINK_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "flow.h"
#include "openvswitch/list.h"

struct dpif;
struct ofpbuf;

struct dpif_netlink_vport {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* ovs_vport header. */
    int dp_ifindex;
    int netnsid;                           /* Network Namespace ID. */
    odp_port_t port_no;                    /* ODPP_NONE if unknown. */
    enum ovs_vport_type type;

    /* Attributes.
     *
     * The 'stats' member points to 64-bit data that might only be aligned on
     * 32-bit boundaries, so use get_unaligned_u64() to access its values.
     */
    const char *name;                      /* OVS_VPORT_ATTR_NAME. */
    uint32_t n_upcall_pids;
    const uint32_t *upcall_pids;           /* OVS_VPORT_ATTR_UPCALL_PID. */
    const struct ovs_vport_stats *stats;   /* OVS_VPORT_ATTR_STATS. */
    uint64_t upcall_success;               /* OVS_VPORT_UPCALL_ATTR_SUCCESS. */
    uint64_t upcall_fail;                  /* OVS_VPORT_UPCALL_ATTR_FAIL. */
    const struct nlattr *options;          /* OVS_VPORT_ATTR_OPTIONS. */
    size_t options_len;
};

void dpif_netlink_vport_init(struct dpif_netlink_vport *);

int dpif_netlink_vport_transact(const struct dpif_netlink_vport *request,
                                struct dpif_netlink_vport *reply,
                                struct ofpbuf **bufp);
int dpif_netlink_vport_get(const char *name, struct dpif_netlink_vport *reply,
                           struct ofpbuf **bufp);

bool dpif_netlink_is_internal_device(const char *name);

enum ovs_vport_type netdev_to_ovs_vport_type(const char *type);

/* Socket map operations. */
struct dpif_netlink_skmap_entry {
    uint32_t key_type;
    ovs_be32 ipv4_src;
    ovs_be32 ipv4_dst;
    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    uint8_t protocol;
    uint8_t sock_state;

    struct ovs_list node;       /* For linking into a list. */
};

int dpif_netlink_get_dp_ifindex(const struct dpif *);
int dpif_netlink_skmap_dump(int dp_ifindex, struct ovs_list *entries);
int dpif_netlink_skmap_get(int dp_ifindex,
                           const struct dpif_netlink_skmap_entry *query,
                           struct dpif_netlink_skmap_entry *reply);
int dpif_netlink_skmap_del(int dp_ifindex,
                           const struct dpif_netlink_skmap_entry *entry);
void dpif_netlink_skmap_entries_free(struct ovs_list *entries);

#endif /* dpif-netlink.h */

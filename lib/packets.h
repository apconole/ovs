/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

#ifndef PACKETS_H
#define PACKETS_H 1

#include <inttypes.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include "compiler.h"
#include "openvswitch/geneve.h"
#include "openvswitch/packets.h"
#include "openvswitch/types.h"
#include "net-proto.h"
#include "openvswitch/nsh.h"
#include "odp-netlink.h"
#include "random.h"
#include "hash.h"
#include "tun-metadata.h"
#include "unaligned.h"
#include "util.h"
#include "timeval.h"

struct dp_packet;
struct conn;
struct ds;

/* Purely internal to OVS userspace. These flags should never be exposed to
 * the outside world and so aren't included in the flags mask. */

/* Tunnel information is in userspace datapath format. */
#define FLOW_TNL_F_UDPIF (1 << 4)

static inline bool
flow_tnl_dst_is_set(const struct flow_tnl *tnl)
{
    return tnl->ip_dst || ipv6_addr_is_set(&tnl->ipv6_dst);
}

static inline bool
flow_tnl_src_is_set(const struct flow_tnl *tnl)
{
    return tnl->ip_src || ipv6_addr_is_set(&tnl->ipv6_src);
}

struct in6_addr flow_tnl_dst(const struct flow_tnl *tnl);
struct in6_addr flow_tnl_src(const struct flow_tnl *tnl);

/* Returns an offset to 'src' covering all the meaningful fields in 'src'. */
static inline size_t
flow_tnl_size(const struct flow_tnl *src)
{
    if (!flow_tnl_dst_is_set(src)) {
        /* Covers ip_dst and ipv6_dst only. */
        return offsetof(struct flow_tnl, ip_src);
    }
    if (src->flags & FLOW_TNL_F_UDPIF) {
        /* Datapath format, cover all options we have. */
        return offsetof(struct flow_tnl, metadata.opts)
            + src->metadata.present.len;
    }
    if (!src->metadata.present.map) {
        /* No TLVs, opts is irrelevant. */
        return offsetof(struct flow_tnl, metadata.opts);
    }
    /* Have decoded TLVs, opts is relevant. */
    return sizeof *src;
}

/* Copy flow_tnl, but avoid copying unused portions of tun_metadata.  Unused
 * data in 'dst' is NOT cleared, so this must not be used in cases where the
 * uninitialized portion may be hashed over. */
static inline void
flow_tnl_copy__(struct flow_tnl *dst, const struct flow_tnl *src)
{
    memcpy(dst, src, flow_tnl_size(src));
}

static inline bool
flow_tnl_equal(const struct flow_tnl *a, const struct flow_tnl *b)
{
    size_t a_size = flow_tnl_size(a);

    return a_size == flow_tnl_size(b) && !memcmp(a, b, a_size);
}

/* Datapath packet metadata */
struct pkt_metadata {
PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
    uint32_t recirc_id;         /* Recirculation id carried with the
                                   recirculating packets. 0 for packets
                                   received from the wire. */
    uint32_t dp_hash;           /* hash value computed by the recirculation
                                   action. */
    uint32_t skb_priority;      /* Packet priority for QoS. */
    uint32_t pkt_mark;          /* Packet mark. */
    uint8_t  ct_state;          /* Connection state. */
    bool ct_orig_tuple_ipv6;
    uint16_t ct_zone;           /* Connection zone. */
    uint32_t ct_mark;           /* Connection mark. */
    ovs_u128 ct_label;          /* Connection label. */
    union flow_in_port in_port; /* Input port. */
    odp_port_t orig_in_port;    /* Originating in_port for tunneled packets */
    struct conn *conn;          /* Cached conntrack connection. */
    bool reply;                 /* True if reply direction. */
    bool icmp_related;          /* True if ICMP related. */
);

PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline1,
    union {                     /* Populated only for non-zero 'ct_state'. */
        struct ovs_key_ct_tuple_ipv4 ipv4;
        struct ovs_key_ct_tuple_ipv6 ipv6;   /* Used only if                */
    } ct_orig_tuple;                         /* 'ct_orig_tuple_ipv6' is set */
);

PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline2,
    struct flow_tnl tunnel;     /* Encapsulating tunnel parameters. Note that
                                 * if 'ip_dst' == 0, the rest of the fields may
                                 * be uninitialized. */
);
};

BUILD_ASSERT_DECL(offsetof(struct pkt_metadata, cacheline0) == 0);
BUILD_ASSERT_DECL(offsetof(struct pkt_metadata, cacheline1) ==
                  CACHE_LINE_SIZE);
BUILD_ASSERT_DECL(offsetof(struct pkt_metadata, cacheline2) ==
                  2 * CACHE_LINE_SIZE);

static inline void
pkt_metadata_init_tnl(struct pkt_metadata *md)
{
    odp_port_t orig_in_port;

    /* Zero up through the tunnel metadata options. The length and table
     * are before this and as long as they are empty, the options won't
     * be looked at. Keep the orig_in_port field. */
    orig_in_port = md->in_port.odp_port;
    memset(md, 0, offsetof(struct pkt_metadata, tunnel.metadata.opts));
    md->orig_in_port = orig_in_port;
}

static inline void
pkt_metadata_init_conn(struct pkt_metadata *md)
{
    md->conn = NULL;
}

static inline void
pkt_metadata_init(struct pkt_metadata *md, odp_port_t port)
{
    /* This is called for every packet in userspace datapath and affects
     * performance if all the metadata is initialized. Hence, fields should
     * only be zeroed out when necessary.
     *
     * Initialize only till ct_state. Once the ct_state is zeroed out rest
     * of ct fields will not be looked at unless ct_state != 0.
     */
    memset(md, 0, offsetof(struct pkt_metadata, ct_orig_tuple_ipv6));

    /* It can be expensive to zero out all of the tunnel metadata. However,
     * we can just zero out ip_dst and the rest of the data will never be
     * looked at. */
    md->tunnel.ip_dst = 0;
    md->tunnel.ipv6_dst = in6addr_any;
    md->in_port.odp_port = port;
    md->orig_in_port = port;
    md->conn = NULL;
}

/* This function prefetches the cachelines touched by pkt_metadata_init()
 * and pkt_metadata_init_tnl().  For performance reasons the two functions
 * should be kept in sync. */
static inline void
pkt_metadata_prefetch_init(struct pkt_metadata *md)
{
    /* Prefetch cacheline0 as members till ct_state and odp_port will
     * be initialized later in pkt_metadata_init(). */
    OVS_PREFETCH(md->cacheline0);

    /* Prefetch cacheline1 as members of this cacheline will be zeroed out
     * in pkt_metadata_init_tnl(). */
    OVS_PREFETCH(md->cacheline1);

    /* Prefetch cachline2 as ip_dst & ipv6_dst fields will be initialized. */
    OVS_PREFETCH(md->cacheline2);
}

void compose_rarp(struct dp_packet *, const struct eth_addr);

void eth_push_vlan(struct dp_packet *, ovs_be16 tpid, ovs_be16 tci);
void eth_pop_vlan(struct dp_packet *);

const char *eth_from_hex(const char *hex, struct dp_packet **packetp);

void set_mpls_lse(struct dp_packet *, ovs_be32 label);
void push_mpls(struct dp_packet *packet, ovs_be16 ethtype, ovs_be32 lse);
void pop_mpls(struct dp_packet *, ovs_be16 ethtype);
void add_mpls(struct dp_packet *packet, ovs_be16 ethtype, ovs_be32 lse,
              bool l3_encap);


void push_eth(struct dp_packet *packet, const struct eth_addr *dst,
              const struct eth_addr *src);
void pop_eth(struct dp_packet *packet);

void push_nsh(struct dp_packet *packet, const struct nsh_hdr *nsh_hdr_src);
bool pop_nsh(struct dp_packet *packet);

/* Connection states.
 *
 * Names like CS_RELATED are bit values, e.g. 1 << 2.
 * Names like CS_RELATED_BIT are bit indexes, e.g. 2. */
#define CS_STATES                               \
    CS_STATE(NEW,         0, "new")             \
    CS_STATE(ESTABLISHED, 1, "est")             \
    CS_STATE(RELATED,     2, "rel")             \
    CS_STATE(REPLY_DIR,   3, "rpl")             \
    CS_STATE(INVALID,     4, "inv")             \
    CS_STATE(TRACKED,     5, "trk")             \
    CS_STATE(SRC_NAT,     6, "snat")            \
    CS_STATE(DST_NAT,     7, "dnat")

enum {
#define CS_STATE(ENUM, INDEX, NAME) \
    CS_##ENUM = 1 << INDEX, \
    CS_##ENUM##_BIT = INDEX,
    CS_STATES
#undef CS_STATE
};

/* Undefined connection state bits. */
enum {
#define CS_STATE(ENUM, INDEX, NAME) +CS_##ENUM
    CS_SUPPORTED_MASK = CS_STATES
#undef CS_STATE
};
#define CS_UNSUPPORTED_MASK  (~(uint32_t)CS_SUPPORTED_MASK)


void *eth_compose(struct dp_packet *, const struct eth_addr eth_dst,
                  const struct eth_addr eth_src, uint16_t eth_type,
                  size_t size);
void *snap_compose(struct dp_packet *, const struct eth_addr eth_dst,
                   const struct eth_addr eth_src,
                   unsigned int oui, uint16_t snap_type, size_t size);
void packet_set_ipv4(struct dp_packet *, ovs_be32 src, ovs_be32 dst, uint8_t tos,
                     uint8_t ttl);
void packet_set_ipv4_addr(struct dp_packet *packet, ovs_16aligned_be32 *addr,
                          ovs_be32 new_addr);
void packet_set_ipv6(struct dp_packet *, const struct in6_addr *src,
                     const struct in6_addr *dst, uint8_t tc,
                     ovs_be32 fl, uint8_t hlmit);
void packet_set_ipv6_addr(struct dp_packet *packet, uint8_t proto,
                          ovs_16aligned_be32 addr[4],
                          const struct in6_addr *new_addr,
                          bool recalculate_csum);
void packet_set_tcp_port(struct dp_packet *, ovs_be16 src, ovs_be16 dst);
void packet_set_udp_port(struct dp_packet *, ovs_be16 src, ovs_be16 dst);
void packet_set_sctp_port(struct dp_packet *, ovs_be16 src, ovs_be16 dst);
void packet_set_icmp(struct dp_packet *, uint8_t type, uint8_t code);
void packet_set_nd(struct dp_packet *, const struct in6_addr *target,
                   const struct eth_addr sll, const struct eth_addr tll);
void packet_set_nd_ext(struct dp_packet *packet,
                       const ovs_16aligned_be32 rso_flags,
                       const uint8_t opt_type);
void packet_set_igmp3_query(struct dp_packet *, uint8_t max_resp,
                            ovs_be32 group, bool srs, uint8_t qrv,
                            uint8_t qqic);
void *compose_ipv6(struct dp_packet *packet, uint8_t proto,
                   const struct in6_addr *src, const struct in6_addr *dst,
                   uint8_t key_tc, ovs_be32 key_fl, uint8_t key_hl, int size);
void compose_arp__(struct dp_packet *);
void compose_arp(struct dp_packet *, uint16_t arp_op,
                 const struct eth_addr arp_sha,
                 const struct eth_addr arp_tha, bool broadcast,
                 ovs_be32 arp_spa, ovs_be32 arp_tpa);
void compose_nd_ns(struct dp_packet *, const struct eth_addr eth_src,
                   const struct in6_addr *ipv6_src,
                   const struct in6_addr *ipv6_dst);
void compose_nd_na(struct dp_packet *, const struct eth_addr eth_src,
                   const struct eth_addr eth_dst,
                   const struct in6_addr *ipv6_src,
                   const struct in6_addr *ipv6_dst,
                   ovs_be32 rso_flags);
void compose_nd_ra(struct dp_packet *,
                   const struct eth_addr eth_src,
                   const struct eth_addr eth_dst,
                   const struct in6_addr *ipv6_src,
                   const struct in6_addr *ipv6_dst,
                   uint8_t cur_hop_limit, uint8_t mo_flags,
                   ovs_be16 router_lt, ovs_be32 reachable_time,
                   ovs_be32 retrans_timer, uint32_t mtu);
void packet_put_ra_prefix_opt(struct dp_packet *,
                              uint8_t plen, uint8_t la_flags,
                              ovs_be32 valid_lifetime,
                              ovs_be32 preferred_lifetime,
                              const ovs_be128 router_prefix);
bool packet_rh_present(struct dp_packet *packet, uint8_t *nexthdr,
                       bool *first_frag);
void IP_ECN_set_ce(struct dp_packet *pkt, bool is_ipv6);
void packet_tcp_complete_csum(struct dp_packet *, bool is_inner);
void packet_udp_complete_csum(struct dp_packet *, bool is_inner);
bool packet_udp_tunnel_csum(struct dp_packet *);
void packet_sctp_complete_csum(struct dp_packet *, bool is_inner);


#endif /* packets.h */

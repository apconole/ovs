/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include "net-proto.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include <netdb.h>
#include "byte-order.h"
#include "csum.h"
#include "crc32c.h"
#include "openvswitch/hmap.h"
#include "openvswitch/dynamic-string.h"
#include "ovs-thread.h"
#include "odp-util.h"
#include "unaligned.h"
#include "util.h"

const struct in6_addr in6addr_exact = IN6ADDR_EXACT_INIT;
const struct in6_addr in6addr_all_hosts = IN6ADDR_ALL_HOSTS_INIT;
const struct in6_addr in6addr_all_routers = IN6ADDR_ALL_ROUTERS_INIT;
const struct in6_addr in6addr_v4mapped_any = IN6ADDR_V4MAPPED_ANY_INIT;

/* Returns true if 's' consists entirely of hex digits, false otherwise. */
static bool
is_all_hex(const char *s)
{
    return s[strspn(s, "0123456789abcdefABCDEF")] == '\0';
}

/* Parses 's' as a 16-digit hexadecimal number representing a datapath ID.  On
 * success stores the dpid into '*dpidp' and returns true, on failure stores 0
 * into '*dpidp' and returns false.
 *
 * Rejects an all-zeros dpid as invalid. */
bool
dpid_from_string(const char *s, uint64_t *dpidp)
{
    size_t len = strlen(s);
    *dpidp = ((len == 16 && is_all_hex(s))
              || (len <= 18 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
                  && is_all_hex(s + 2))
              ? strtoull(s, NULL, 16)
              : 0);
    return *dpidp != 0;
}

/* Parses string 's', which must be an IPv4 address.  Stores the IPv4 address
 * into '*ip'.  Returns true if successful, otherwise false. */
bool
ip_parse(const char *s, ovs_be32 *ip)
{
    return inet_pton(AF_INET, s, ip) == 1;
}

/* Parses string 's', which must be an IP address with a port number
 * with ":" as a separator (e.g.: 192.168.1.2:80).
 * Stores the IP address into '*ip' and port number to '*port'.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ip_parse_port(const char *s, ovs_be32 *ip, ovs_be16 *port)
{
    int n = 0;
    if (ovs_scan(s, IP_PORT_SCAN_FMT"%n", IP_PORT_SCAN_ARGS(ip, port), &n)
        && !s[n]) {
        return NULL;
    }

    return xasprintf("%s: invalid IP address or port number", s);
}

/* Parses string 's', which must be an IP address with an optional netmask or
 * CIDR prefix length.  Stores the IP address into '*ip', netmask into '*mask',
 * (255.255.255.255, if 's' lacks a netmask), and number of scanned characters
 * into '*n'.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ip_parse_masked_len(const char *s, int *n, ovs_be32 *ip,
                    ovs_be32 *mask)
{
    int prefix;

    if (ovs_scan_len(s, n, IP_SCAN_FMT"/"IP_SCAN_FMT,
                 IP_SCAN_ARGS(ip), IP_SCAN_ARGS(mask))) {
        /* OK. */
    } else if (ovs_scan_len(s, n, IP_SCAN_FMT"/%d",
                            IP_SCAN_ARGS(ip), &prefix)) {
        if (prefix < 0 || prefix > 32) {
            return xasprintf("%s: IPv4 network prefix bits not between 0 and "
                              "32, inclusive", s);
        }
        *mask = be32_prefix_mask(prefix);
    } else if (ovs_scan_len(s, n, IP_SCAN_FMT, IP_SCAN_ARGS(ip))) {
        *mask = OVS_BE32_MAX;
    } else {
        return xasprintf("%s: invalid IP address", s);
    }
    return NULL;
}

/* This function is similar to ip_parse_masked_len(), but doesn't return the
 * number of scanned characters and expects 's' to end after the ip/(optional)
 * mask.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ip_parse_masked(const char *s, ovs_be32 *ip, ovs_be32 *mask)
{
    int n = 0;

    char *error = ip_parse_masked_len(s, &n, ip, mask);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IP address", s);
    }
    return error;
}

/* Similar to ip_parse_masked_len(), but the mask, if present, must be a CIDR
 * mask and is returned as a prefix len in '*plen'. */
char * OVS_WARN_UNUSED_RESULT
ip_parse_cidr_len(const char *s, int *n, ovs_be32 *ip, unsigned int *plen)
{
    ovs_be32 mask;
    char *error;

    error = ip_parse_masked_len(s, n, ip, &mask);
    if (error) {
        return error;
    }

    if (!ip_is_cidr(mask)) {
        return xasprintf("%s: CIDR network required", s);
    }
    *plen = ip_count_cidr_bits(mask);
    return NULL;
}

/* Similar to ip_parse_cidr_len(), but doesn't return the number of scanned
 * characters and expects 's' to be NULL terminated at the end of the
 * ip/(optional) cidr. */
char * OVS_WARN_UNUSED_RESULT
ip_parse_cidr(const char *s, ovs_be32 *ip, unsigned int *plen)
{
    int n = 0;

    char *error = ip_parse_cidr_len(s, &n, ip, plen);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IP address", s);
    }
    return error;
}

/* Given the IP netmask 'netmask', returns the number of bits of the IP address
 * that it specifies, that is, the number of 1-bits in 'netmask'.
 *
 * If 'netmask' is not a CIDR netmask (see ip_is_cidr()), the return value will
 * still be in the valid range but isn't otherwise meaningful. */
int
ip_count_cidr_bits(ovs_be32 netmask)
{
    return 32 - ctz32(ntohl(netmask));
}

/* Parses string 's', which must be an IPv6 address.  Stores the IPv6 address
 * into '*ip'.  Returns true if successful, otherwise false. */
bool
ipv6_parse(const char *s, struct in6_addr *ip)
{
    return inet_pton(AF_INET6, s, ip) == 1;
}

/* Parses string 's', which must be an IPv6 address with an optional netmask or
 * CIDR prefix length.  Stores the IPv6 address into '*ip' and the netmask into
 * '*mask' (if 's' does not contain a netmask, all-one-bits is assumed), and
 * number of scanned characters into '*n'.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_masked_len(const char *s, int *n, struct in6_addr *ip,
                      struct in6_addr *mask)
{
    char ipv6_s[IPV6_SCAN_LEN + 1];
    int prefix;

    if (ovs_scan_len(s, n, " "IPV6_SCAN_FMT, ipv6_s)
        && ipv6_parse(ipv6_s, ip)) {
        if (ovs_scan_len(s, n, "/%d", &prefix)) {
            if (prefix < 0 || prefix > 128) {
                return xasprintf("%s: IPv6 network prefix bits not between 0 "
                                 "and 128, inclusive", s);
            }
            *mask = ipv6_create_mask(prefix);
        } else if (ovs_scan_len(s, n, "/"IPV6_SCAN_FMT, ipv6_s)) {
             if (!ipv6_parse(ipv6_s, mask)) {
                 return xasprintf("%s: Invalid IPv6 mask", s);
             }
            /* OK. */
        } else {
            /* OK. No mask. */
            *mask = in6addr_exact;
        }
        return NULL;
    }
    return xasprintf("%s: invalid IPv6 address", s);
}

/* This function is similar to ipv6_parse_masked_len(), but doesn't return the
 * number of scanned characters and expects 's' to end following the
 * ipv6/(optional) mask. */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_masked(const char *s, struct in6_addr *ip, struct in6_addr *mask)
{
    int n = 0;

    char *error = ipv6_parse_masked_len(s, &n, ip, mask);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IPv6 address", s);
    }
    return error;
}

/* Similar to ipv6_parse_masked_len(), but the mask, if present, must be a CIDR
 * mask and is returned as a prefix length in '*plen'. */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_cidr_len(const char *s, int *n, struct in6_addr *ip,
                    unsigned int *plen)
{
    struct in6_addr mask;
    char *error;

    error = ipv6_parse_masked_len(s, n, ip, &mask);
    if (error) {
        return error;
    }

    if (!ipv6_is_cidr(&mask)) {
        return xasprintf("%s: IPv6 CIDR network required", s);
    }
    *plen = ipv6_count_cidr_bits(&mask);
    return NULL;
}

/* Similar to ipv6_parse_cidr_len(), but doesn't return the number of scanned
 * characters and expects 's' to end after the ipv6/(optional) cidr. */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_cidr(const char *s, struct in6_addr *ip, unsigned int *plen)
{
    int n = 0;

    char *error = ipv6_parse_cidr_len(s, &n, ip, plen);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IPv6 address", s);
    }
    return error;
}

/* Returns an in6_addr consisting of 'mask' high-order 1-bits and 128-N
 * low-order 0-bits. */
struct in6_addr
ipv6_create_mask(int mask)
{
    struct in6_addr netmask;
    uint8_t *netmaskp = &netmask.s6_addr[0];

    memset(&netmask, 0, sizeof netmask);
    while (mask > 8) {
        *netmaskp = 0xff;
        netmaskp++;
        mask -= 8;
    }

    if (mask) {
        *netmaskp = 0xff << (8 - mask);
    }

    return netmask;
}

/* Given the IPv6 netmask 'netmask', returns the number of bits of the IPv6
 * address that it specifies, that is, the number of 1-bits in 'netmask'.
 * 'netmask' must be a CIDR netmask (see ipv6_is_cidr()).
 *
 * If 'netmask' is not a CIDR netmask (see ipv6_is_cidr()), the return value
 * will still be in the valid range but isn't otherwise meaningful. */
int
ipv6_count_cidr_bits(const struct in6_addr *netmask)
{
    int i;
    int count = 0;
    const uint8_t *netmaskp = &netmask->s6_addr[0];

    for (i=0; i<16; i++) {
        if (netmaskp[i] == 0xff) {
            count += 8;
        } else {
            uint8_t nm;

            for(nm = netmaskp[i]; nm; nm <<= 1) {
                count++;
            }
            break;
        }

    }

    return count;
}

/* Stores the string representation of the IPv6 address 'addr' into the
 * character array 'addr_str', which must be at least INET6_ADDRSTRLEN
 * bytes long. If addr is IPv4-mapped, store an IPv4 dotted-decimal string. */
const char *
ipv6_string_mapped(char *addr_str, const struct in6_addr *addr)
{
    ovs_be32 ip;
    ip = in6_addr_get_mapped_ipv4(addr);
    if (ip) {
        return inet_ntop(AF_INET, &ip, addr_str, INET6_ADDRSTRLEN);
    } else {
        return inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
    }
}

/* Returns true if 'netmask' is a CIDR netmask, that is, if it consists of N
 * high-order 1-bits and 128-N low-order 0-bits. */
bool
ipv6_is_cidr(const struct in6_addr *netmask)
{
    const uint8_t *netmaskp = &netmask->s6_addr[0];
    int i;

    for (i=0; i<16; i++) {
        if (netmaskp[i] != 0xff) {
            uint8_t x = ~netmaskp[i];
            if (x & (x + 1)) {
                return false;
            }
            while (++i < 16) {
                if (netmaskp[i]) {
                    return false;
                }
            }
            return true;
        }
    }
    return true;
}

uint64_t
eth_addr_to_uint64(const struct eth_addr ea)
{
    return (((uint64_t) ntohs(ea.be16[0]) << 32)
            | ((uint64_t) ntohs(ea.be16[1]) << 16)
            | ntohs(ea.be16[2]));
}

void
eth_addr_from_uint64(uint64_t x, struct eth_addr *ea)
{
    ea->be16[0] = htons(x >> 32);
    ea->be16[1] = htons((x & 0xFFFF0000) >> 16);
    ea->be16[2] = htons(x & 0xFFFF);
}

void
eth_addr_mark_random(struct eth_addr *ea)
{
    ea->ea[0] &= ~1;                /* Unicast. */
    ea->ea[0] |= 2;                 /* Private. */
}

/* Returns true if 'ea' is a reserved address, that a bridge must never
 * forward, false otherwise.
 *
 * If you change this function's behavior, please update corresponding
 * documentation in vswitch.xml at the same time. */
bool
eth_addr_is_reserved(const struct eth_addr ea)
{
    struct eth_addr_node {
        struct hmap_node hmap_node;
        const uint64_t ea64;
    };

    static struct eth_addr_node nodes[] = {
        /* STP, IEEE pause frames, and other reserved protocols. */
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000000ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000001ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000002ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000003ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000004ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000005ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000006ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000007ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000008ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000009ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000aULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000bULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000cULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000dULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000eULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000fULL },

        /* Extreme protocols. */
        { HMAP_NODE_NULL_INITIALIZER, 0x00e02b000000ULL }, /* EDP. */
        { HMAP_NODE_NULL_INITIALIZER, 0x00e02b000004ULL }, /* EAPS. */
        { HMAP_NODE_NULL_INITIALIZER, 0x00e02b000006ULL }, /* EAPS. */

        /* Cisco protocols. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000c000000ULL }, /* ISL. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccccULL }, /* PAgP, UDLD, CDP,
                                                            * DTP, VTP. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000ccccccdULL }, /* PVST+. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000ccdcdcdULL }, /* STP Uplink Fast,
                                                            * FlexLink. */

        /* Cisco CFM. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc0ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc1ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc2ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc3ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc4ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc5ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc6ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc7ULL },
    };

    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct eth_addr_node *node;
    static struct hmap addrs;
    uint64_t ea64;

    if (ovsthread_once_start(&once)) {
        hmap_init(&addrs);
        for (node = nodes; node < &nodes[ARRAY_SIZE(nodes)]; node++) {
            hmap_insert(&addrs, &node->hmap_node, hash_uint64(node->ea64));
        }
        ovsthread_once_done(&once);
    }

    ea64 = eth_addr_to_uint64(ea);
    HMAP_FOR_EACH_IN_BUCKET (node, hmap_node, hash_uint64(ea64), &addrs) {
        if (node->ea64 == ea64) {
            return true;
        }
    }
    return false;
}

/* Attempts to parse 's' as an Ethernet address.  If successful, stores the
 * address in 'ea' and returns true, otherwise zeros 'ea' and returns
 * false.  This function checks trailing characters. */
bool
eth_addr_from_string(const char *s, struct eth_addr *ea)
{
    int n = 0;
    if (ovs_scan(s, ETH_ADDR_SCAN_FMT"%n", ETH_ADDR_SCAN_ARGS(*ea), &n)
        && !s[n]) {
        return true;
    } else {
        *ea = eth_addr_zero;
        return false;
    }
}

/* Set time to live (TTL) of an MPLS label stack entry (LSE). */
void
set_mpls_lse_ttl(ovs_be32 *lse, uint8_t ttl)
{
    *lse &= ~htonl(MPLS_TTL_MASK);
    *lse |= htonl((ttl << MPLS_TTL_SHIFT) & MPLS_TTL_MASK);
}

/* Set traffic class (TC) of an MPLS label stack entry (LSE). */
void
set_mpls_lse_tc(ovs_be32 *lse, uint8_t tc)
{
    *lse &= ~htonl(MPLS_TC_MASK);
    *lse |= htonl((tc << MPLS_TC_SHIFT) & MPLS_TC_MASK);
}

/* Set label of an MPLS label stack entry (LSE). */
void
set_mpls_lse_label(ovs_be32 *lse, ovs_be32 label)
{
    *lse &= ~htonl(MPLS_LABEL_MASK);
    *lse |= htonl((ntohl(label) << MPLS_LABEL_SHIFT) & MPLS_LABEL_MASK);
}

/* Set bottom of stack (BoS) bit of an MPLS label stack entry (LSE). */
void
set_mpls_lse_bos(ovs_be32 *lse, uint8_t bos)
{
    *lse &= ~htonl(MPLS_BOS_MASK);
    *lse |= htonl((bos << MPLS_BOS_SHIFT) & MPLS_BOS_MASK);
}

/* Compose an MPLS label stack entry (LSE) from its components:
 * label, traffic class (TC), time to live (TTL) and
 * bottom of stack (BoS) bit. */
ovs_be32
set_mpls_lse_values(uint8_t ttl, uint8_t tc, uint8_t bos, ovs_be32 label)
{
    ovs_be32 lse = htonl(0);
    set_mpls_lse_ttl(&lse, ttl);
    set_mpls_lse_tc(&lse, tc);
    set_mpls_lse_bos(&lse, bos);
    set_mpls_lse_label(&lse, label);
    return lse;
}

void
eth_format_masked(const struct eth_addr eth,
                  const struct eth_addr *mask, struct ds *s)
{
    ds_put_format(s, ETH_ADDR_FMT, ETH_ADDR_ARGS(eth));
    if (mask && !eth_mask_is_exact(*mask)) {
        ds_put_format(s, "/"ETH_ADDR_FMT, ETH_ADDR_ARGS(*mask));
    }
}

void
in6_addr_solicited_node(struct in6_addr *addr, const struct in6_addr *ip6)
{
    union ovs_16aligned_in6_addr *taddr =
        (union ovs_16aligned_in6_addr *) addr;
    memset(taddr->be16, 0, sizeof(taddr->be16));
    taddr->be16[0] = htons(0xff02);
    taddr->be16[5] = htons(0x1);
    taddr->be16[6] = htons(0xff00);
    memcpy(&addr->s6_addr[13], &ip6->s6_addr[13], 3);
}

/*
 * Generates ipv6 EUI64 address from the given eth addr
 * and prefix and stores it in 'lla'
 */
void
in6_generate_eui64(struct eth_addr ea, const struct in6_addr *prefix,
                   struct in6_addr *lla)
{
    union ovs_16aligned_in6_addr *taddr =
        (union ovs_16aligned_in6_addr *) lla;
    union ovs_16aligned_in6_addr *prefix_taddr =
        (union ovs_16aligned_in6_addr *) prefix;
    taddr->be16[0] = prefix_taddr->be16[0];
    taddr->be16[1] = prefix_taddr->be16[1];
    taddr->be16[2] = prefix_taddr->be16[2];
    taddr->be16[3] = prefix_taddr->be16[3];
    taddr->be16[4] = htons(((ea.ea[0] ^ 0x02) << 8) | ea.ea[1]);
    taddr->be16[5] = htons(ea.ea[2] << 8 | 0x00ff);
    taddr->be16[6] = htons(0xfe << 8 | ea.ea[3]);
    taddr->be16[7] = ea.be16[2];
}

/* Generates ipv6 link local address from the given eth addr
 * with prefix 'fe80::/64' and stores it in 'lla'. */
void
in6_generate_lla(struct eth_addr ea, struct in6_addr *lla)
{
    union ovs_16aligned_in6_addr *taddr =
        (union ovs_16aligned_in6_addr *) lla;
    memset(taddr->be16, 0, sizeof(taddr->be16));
    taddr->be16[0] = htons(0xfe80);
    taddr->be16[4] = htons(((ea.ea[0] ^ 0x02) << 8) | ea.ea[1]);
    taddr->be16[5] = htons(ea.ea[2] << 8 | 0x00ff);
    taddr->be16[6] = htons(0xfe << 8 | ea.ea[3]);
    taddr->be16[7] = ea.be16[2];
}

/* Returns true if 'addr' is a link local address.  Otherwise, false. */
bool
in6_is_lla(struct in6_addr *addr)
{
#ifdef s6_addr32
    return addr->s6_addr32[0] == htonl(0xfe800000) && !(addr->s6_addr32[1]);
#else
    return addr->s6_addr[0] == 0xfe && addr->s6_addr[1] == 0x80 &&
         !(addr->s6_addr[2] | addr->s6_addr[3] | addr->s6_addr[4] |
           addr->s6_addr[5] | addr->s6_addr[6] | addr->s6_addr[7]);
#endif
}

void
ipv6_multicast_to_ethernet(struct eth_addr *eth, const struct in6_addr *ip6)
{
    eth->ea[0] = 0x33;
    eth->ea[1] = 0x33;
    eth->ea[2] = ip6->s6_addr[12];
    eth->ea[3] = ip6->s6_addr[13];
    eth->ea[4] = ip6->s6_addr[14];
    eth->ea[5] = ip6->s6_addr[15];
}

void
ip_format_masked(ovs_be32 ip, ovs_be32 mask, struct ds *s)
{
    ds_put_format(s, IP_FMT, IP_ARGS(ip));
    if (mask != OVS_BE32_MAX) {
        if (ip_is_cidr(mask)) {
            ds_put_format(s, "/%d", ip_count_cidr_bits(mask));
        } else {
            ds_put_format(s, "/"IP_FMT, IP_ARGS(mask));
        }
    }
}

/* Stores the string representation of the IPv6 address 'addr' into the
 * character array 'addr_str', which must be at least INET6_ADDRSTRLEN
 * bytes long. */
void
ipv6_format_addr(const struct in6_addr *addr, struct ds *s)
{
    char *dst;

    ds_reserve(s, s->length + INET6_ADDRSTRLEN);

    dst = s->string + s->length;
    inet_ntop(AF_INET6, addr, dst, INET6_ADDRSTRLEN);
    s->length += strlen(dst);
}

/* Same as print_ipv6_addr, but optionally encloses the address in square
 * brackets. */
void
ipv6_format_addr_bracket(const struct in6_addr *addr, struct ds *s,
                         bool bracket)
{
    if (bracket) {
        ds_put_char(s, '[');
    }
    ipv6_format_addr(addr, s);
    if (bracket) {
        ds_put_char(s, ']');
    }
}

void
ipv6_format_mapped(const struct in6_addr *addr, struct ds *s)
{
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        ds_put_format(s, IP_FMT, addr->s6_addr[12], addr->s6_addr[13],
                                 addr->s6_addr[14], addr->s6_addr[15]);
    } else {
        ipv6_format_addr(addr, s);
    }
}

void
ipv6_format_masked(const struct in6_addr *addr, const struct in6_addr *mask,
                   struct ds *s)
{
    ipv6_format_addr(addr, s);
    if (mask && !ipv6_mask_is_exact(mask)) {
        if (ipv6_is_cidr(mask)) {
            int cidr_bits = ipv6_count_cidr_bits(mask);
            ds_put_format(s, "/%d", cidr_bits);
        } else {
            ds_put_char(s, '/');
            ipv6_format_addr(mask, s);
        }
    }
}

#ifdef s6_addr32
#define s6_addrX s6_addr32
#define IPV6_FOR_EACH(VAR) for (int VAR = 0; VAR < 4; VAR++)
#else
#define s6_addrX s6_addr
#define IPV6_FOR_EACH(VAR) for (int VAR = 0; VAR < 16; VAR++)
#endif

struct in6_addr
ipv6_addr_bitand(const struct in6_addr *a, const struct in6_addr *b)
{
   struct in6_addr dst;
   IPV6_FOR_EACH (i) {
       dst.s6_addrX[i] = a->s6_addrX[i] & b->s6_addrX[i];
   }
   return dst;
}

struct in6_addr
ipv6_addr_bitxor(const struct in6_addr *a, const struct in6_addr *b)
{
   struct in6_addr dst;
   IPV6_FOR_EACH (i) {
       dst.s6_addrX[i] = a->s6_addrX[i] ^ b->s6_addrX[i];
   }
   return dst;
}

bool
ipv6_is_zero(const struct in6_addr *a)
{
   IPV6_FOR_EACH (i) {
       if (a->s6_addrX[i]) {
           return false;
       }
   }
   return true;
}

bool
ipv6_addr_equals_masked(const struct in6_addr *a, const struct in6_addr *b,
                        int plen)
{
    struct in6_addr mask;
    struct in6_addr ma;
    struct in6_addr mb;

    if (plen == 128) {
        return ipv6_addr_equals(a, b);
    }

    mask = ipv6_create_mask(plen);
    ma = ipv6_addr_bitand(a, &mask);
    mb = ipv6_addr_bitand(b, &mask);

    return ipv6_addr_equals(&ma, &mb);
}

void
ip_set_ipv6_flow_label(ovs_16aligned_be32 *flow_label, ovs_be32 flow_key)
{
    ovs_be32 old_label = get_16aligned_be32(flow_label);
    ovs_be32 new_label = (old_label & htonl(~IPV6_LABEL_MASK)) | flow_key;
    put_16aligned_be32(flow_label, new_label);
}

void
ip_set_ipv6_tc(ovs_16aligned_be32 *flow_label, uint8_t tc)
{
    ovs_be32 old_label = get_16aligned_be32(flow_label);
    ovs_be32 new_label = (old_label & htonl(0xF00FFFFF)) | htonl(tc << 20);
    put_16aligned_be32(flow_label, new_label);
}

const char *
tcp_flag_to_string(uint32_t flag)
{
    switch (flag) {
    case TCP_FIN:
        return "fin";
    case TCP_SYN:
        return "syn";
    case TCP_RST:
        return "rst";
    case TCP_PSH:
        return "psh";
    case TCP_ACK:
        return "ack";
    case TCP_URG:
        return "urg";
    case TCP_ECE:
        return "ece";
    case TCP_CWR:
        return "cwr";
    case TCP_NS:
        return "ns";
    case 0x200:
        return "[200]";
    case 0x400:
        return "[400]";
    case 0x800:
        return "[800]";
    default:
        return NULL;
    }
}

/* Appends a string representation of the TCP flags value 'tcp_flags'
 * (e.g. from struct flow.tcp_flags or obtained via TCP_FLAGS) to 's', in the
 * format used by tcpdump. */
void
format_tcp_flags(struct ds *s, uint16_t tcp_flags)
{
    if (!tcp_flags) {
        ds_put_cstr(s, "none");
        return;
    }

    if (tcp_flags & TCP_SYN) {
        ds_put_char(s, 'S');
    }
    if (tcp_flags & TCP_FIN) {
        ds_put_char(s, 'F');
    }
    if (tcp_flags & TCP_PSH) {
        ds_put_char(s, 'P');
    }
    if (tcp_flags & TCP_RST) {
        ds_put_char(s, 'R');
    }
    if (tcp_flags & TCP_URG) {
        ds_put_char(s, 'U');
    }
    if (tcp_flags & TCP_ACK) {
        ds_put_char(s, '.');
    }
    if (tcp_flags & TCP_ECE) {
        ds_put_cstr(s, "E");
    }
    if (tcp_flags & TCP_CWR) {
        ds_put_cstr(s, "C");
    }
    if (tcp_flags & TCP_NS) {
        ds_put_cstr(s, "N");
    }
    if (tcp_flags & 0x200) {
        ds_put_cstr(s, "[200]");
    }
    if (tcp_flags & 0x400) {
        ds_put_cstr(s, "[400]");
    }
    if (tcp_flags & 0x800) {
        ds_put_cstr(s, "[800]");
    }
}

uint32_t
ip_csum_pseudoheader(const struct ip_header *ip)
{
    uint32_t partial = 0;

    partial = csum_add32(partial, get_16aligned_be32(&ip->ip_src));
    partial = csum_add32(partial, get_16aligned_be32(&ip->ip_dst));
    partial = csum_add16(partial, htons(ip->ip_proto));
    partial = csum_add16(partial, htons(ntohs(ip->ip_tot_len) -
                                        IP_IHL(ip->ip_ihl_ver) * 4));

    return partial;
}

#ifndef __CHECKER__
uint32_t
ip_csum_pseudoheader6(const struct ovs_16aligned_ip6_hdr *ip6)
{
    uint32_t partial = 0;

    partial = csum_continue(partial, &ip6->ip6_src, sizeof ip6->ip6_src);
    partial = csum_continue(partial, &ip6->ip6_dst, sizeof ip6->ip6_dst);
    partial = csum_add16(partial, htons(ip6->ip6_nxt));
    partial = csum_add16(partial, ip6->ip6_plen);

    return partial;
}

/* Calculate the IPv6 upper layer checksum according to RFC2460. We pass the
   ip6_nxt and ip6_plen values, so it will also work if extension headers
   are present. */
ovs_be16
ip_csum_upperlayer6(const struct ovs_16aligned_ip6_hdr *ip6,
                        const void *data, uint8_t l4_protocol,
                        uint16_t l4_size)
{
    uint32_t partial = 0;

    partial = csum_continue(partial, &ip6->ip6_src, sizeof ip6->ip6_src);
    partial = csum_continue(partial, &ip6->ip6_dst, sizeof ip6->ip6_dst);
    partial = csum_add16(partial, htons(l4_protocol));
    partial = csum_add16(partial, htons(l4_size));

    partial = csum_continue(partial, data, l4_size);

    return csum_finish(partial);
}
#endif


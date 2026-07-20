/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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

#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>

#include "conntrack-private.h"
#include "csum.h"
#include "dp-packet.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "unaligned.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(conntrack_ftp);

/* FTP ALG mode: whether the data connection is initiated by the client
 * (active) or the server (passive), and whether the session uses IPv6
 * extensions (EPRT/EPSV). */
enum ct_alg_mode {
    CT_FTP_MODE_ACTIVE,
    CT_FTP_MODE_PASSIVE,
    CT_TFTP_MODE,
};

/* String buffer used for parsing FTP string messages.
 * This is sized about twice what is needed to leave some
 * margin of error. */
#define LARGEST_FTP_MSG_OF_INTEREST 128
/* FTP port string used in active mode. */
#define FTP_PORT_CMD "PORT"
/* FTP pasv string used in passive mode. */
#define FTP_PASV_REPLY_CODE "227"
/* FTP epsv string used in passive mode. */
#define FTP_EPSV_REPLY_CODE "229"
/* Maximum decimal digits for port in FTP command.
 * The port is represented as two 3 digit numbers with the
 * high part a multiple of 256. */
#define MAX_FTP_PORT_DGTS 3

/* FTP extension EPRT string used for active mode. */
#define FTP_EPRT_CMD "EPRT"
/* FTP extension EPSV string used for passive mode. */
#define FTP_EPSV_REPLY "EXTENDED PASSIVE"
/* Maximum decimal digits for port in FTP extended command. */
#define MAX_EXT_FTP_PORT_DGTS 5
/* FTP extended command code for IPv4. */
#define FTP_AF_V4 '1'
/* FTP extended command code for IPv6. */
#define FTP_AF_V6 '2'

static bool
is_ftp_ctl(const enum ct_alg_ctl_type ct_alg_ctl)
{
    return ct_alg_ctl == CT_ALG_CTL_FTP;
}

static void
replace_substring(char *substr, size_t substr_size,
                  size_t total_size, char *rep_str,
                  size_t rep_str_size)
{
    memmove(substr + rep_str_size, substr + substr_size,
            total_size - substr_size);
    memcpy(substr, rep_str, rep_str_size);
}

static void
repl_bytes(char *str, char c1, char c2, int max)
{
    while (*str) {
        if (*str == c1) {
            *str = c2;

            if (--max == 0) {
                break;
            }
        }
        str++;
    }
}

/* Replaces a substring in the packet and rewrites the packet
 * size to match.  This function assumes the caller has verified
 * the lengths to prevent under/over flow. */
static void
modify_packet(struct dp_packet *pkt, char *pkt_str, size_t size,
              char *repl_str, size_t repl_size,
              uint32_t orig_used_size)
{
    replace_substring(pkt_str, size,
                      (const char *) dp_packet_tail(pkt) - pkt_str,
                      repl_str, repl_size);
    dp_packet_set_size(pkt, orig_used_size + (int) repl_size - (int) size);
}

/* Replace IPV4 address in FTP message with NATed address. */
static int
repl_ftp_v4_addr(struct dp_packet *pkt, ovs_be32 v4_addr_rep,
                 char *ftp_data_start,
                 size_t addr_offset_from_ftp_data_start,
                 size_t addr_size)
{
    enum { MAX_FTP_V4_NAT_DELTA = 8 };

    /* EPSV mode. */
    if (addr_offset_from_ftp_data_start == 0 &&
        addr_size == 0) {
        return 0;
    }

    /* Do conservative check for pathological MTU usage. */
    uint32_t orig_used_size = dp_packet_size(pkt);
    if (orig_used_size + MAX_FTP_V4_NAT_DELTA >
        dp_packet_get_allocated(pkt)) {

        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "Unsupported effective MTU %u used with FTP V4",
                     dp_packet_get_allocated(pkt));
        return 0;
    }

    char v4_addr_str[INET_ADDRSTRLEN] = {0};
    ovs_assert(inet_ntop(AF_INET, &v4_addr_rep, v4_addr_str,
                         sizeof v4_addr_str));
    repl_bytes(v4_addr_str, '.', ',', 0);
    modify_packet(pkt, ftp_data_start + addr_offset_from_ftp_data_start,
                  addr_size, v4_addr_str, strlen(v4_addr_str),
                  orig_used_size);
    return (int) strlen(v4_addr_str) - (int) addr_size;
}

static char *
skip_non_digits(char *str)
{
    while (!isdigit(*str) && *str != 0) {
        str++;
    }
    return str;
}

static char *
terminate_number_str(char *str, uint8_t max_digits)
{
    uint8_t digits_found = 0;
    while (isdigit(*str) && digits_found <= max_digits) {
        str++;
        digits_found++;
    }

    *str = 0;
    return str;
}

static void
get_ftp_ctl_msg(struct dp_packet *pkt, char *ftp_msg)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    char *tcp_hdr = (char *) th;
    uint32_t tcp_payload_len = dp_packet_get_tcp_payload_length(pkt);
    size_t tcp_payload_of_interest = MIN(tcp_payload_len,
                                         LARGEST_FTP_MSG_OF_INTEREST);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;

    ovs_strlcpy(ftp_msg, tcp_hdr + tcp_hdr_len,
                tcp_payload_of_interest);
}

static enum ftp_ctl_pkt
detect_ftp_ctl_type(const struct conn_lookup_ctx *ctx,
                    struct dp_packet *pkt)
{
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);

    if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        if (strncasecmp(ftp_msg, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD)) &&
            !strcasestr(ftp_msg, FTP_EPSV_REPLY)) {
            return CT_FTP_CTL_OTHER;
        }
    } else {
        if (strncasecmp(ftp_msg, FTP_PORT_CMD, strlen(FTP_PORT_CMD)) &&
            strncasecmp(ftp_msg, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD)) &&
            strncasecmp(ftp_msg, FTP_PASV_REPLY_CODE,
                        strlen(FTP_PASV_REPLY_CODE)) &&
            strncasecmp(ftp_msg, FTP_EPSV_REPLY_CODE,
                        strlen(FTP_EPSV_REPLY_CODE))) {
            return CT_FTP_CTL_OTHER;
        }
    }

    return CT_FTP_CTL_INTEREST;
}

static enum ftp_ctl_pkt
process_ftp_ctl_v4(struct conntrack *ct,
                   struct dp_packet *pkt,
                   const struct conn *conn_for_expectation,
                   ovs_be32 *v4_addr_rep,
                   char **ftp_data_v4_start,
                   size_t *addr_offset_from_ftp_data_start,
                   size_t *addr_size)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    char *tcp_hdr = (char *) th;
    *ftp_data_v4_start = tcp_hdr + tcp_hdr_len;
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);
    char *ftp = ftp_msg;
    struct in_addr ip_addr;
    enum ct_alg_mode mode;
    bool extended = false;

    if (!strncasecmp(ftp, FTP_PORT_CMD, strlen(FTP_PORT_CMD))) {
        ftp = ftp_msg + strlen(FTP_PORT_CMD);
        mode = CT_FTP_MODE_ACTIVE;
    } else if (!strncasecmp(ftp, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD))) {
        ftp = ftp_msg + strlen(FTP_EPRT_CMD);
        mode = CT_FTP_MODE_ACTIVE;
        extended = true;
    } else if (!strncasecmp(ftp, FTP_EPSV_REPLY_CODE,
                            strlen(FTP_EPSV_REPLY_CODE))) {
        ftp = ftp_msg + strlen(FTP_EPSV_REPLY_CODE);
        mode = CT_FTP_MODE_PASSIVE;
        extended = true;
    } else {
        ftp = ftp_msg + strlen(FTP_PASV_REPLY_CODE);
        mode = CT_FTP_MODE_PASSIVE;
    }

    /* Find first space. */
    ftp = strchr(ftp, ' ');
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }

    /* Find the first digit, after space. */
    ftp = skip_non_digits(ftp);
    if (*ftp == 0) {
        return CT_FTP_CTL_INVALID;
    }

    /* EPRT, verify address family. */
    if (extended && mode == CT_FTP_MODE_ACTIVE) {
        if (ftp[0] != FTP_AF_V4 || isdigit(ftp[1])) {
            return CT_FTP_CTL_INVALID;
        }

        ftp = skip_non_digits(ftp + 1);
        if (*ftp == 0) {
            return CT_FTP_CTL_INVALID;
        }
    }

    if (!extended || mode == CT_FTP_MODE_ACTIVE) {
        char *ip_addr_start = ftp;
        *addr_offset_from_ftp_data_start = ip_addr_start - ftp_msg;
        repl_bytes(ftp, ',', '.', 3);

        /* Advance to end of IP address, to terminate it. */
        while (*ftp) {
            if (!isdigit(*ftp) && *ftp != '.') {
                break;
            }
            ftp++;
        }
        *ftp = 0;
        ftp++;

        int rc2 = inet_pton(AF_INET, ip_addr_start, &ip_addr);
        if (rc2 != 1) {
            return CT_FTP_CTL_INVALID;
        }

        *addr_size = ftp - ip_addr_start - 1;
    } else {
        *addr_size = 0;
        *addr_offset_from_ftp_data_start = 0;
    }

    char *save_ftp = ftp;
    uint16_t port_hs;

    if (!extended) {
        ftp = terminate_number_str(ftp, MAX_FTP_PORT_DGTS);
        if (!ftp) {
            return CT_FTP_CTL_INVALID;
        }
        int value;
        if (!str_to_int(save_ftp, 10, &value)) {
            return CT_FTP_CTL_INVALID;
        }

        /* This is derived from the L4 port maximum is 65535. */
        if (value > 255) {
            return CT_FTP_CTL_INVALID;
        }

        port_hs = value;
        port_hs <<= 8;

        /* Skip over comma. */
        ftp++;
        save_ftp = ftp;
        bool digit_found = false;
        while (isdigit(*ftp)) {
            ftp++;
            digit_found = true;
        }
        if (!digit_found) {
            return CT_FTP_CTL_INVALID;
        }
        *ftp = 0;
        if (!str_to_int(save_ftp, 10, &value)) {
            return CT_FTP_CTL_INVALID;
        }

        if (value > 255) {
            return CT_FTP_CTL_INVALID;
        }

        port_hs |= value;
    } else {
        ftp = terminate_number_str(ftp, MAX_EXT_FTP_PORT_DGTS);
        if (!ftp) {
            return CT_FTP_CTL_INVALID;
        }
        int value;
        if (!str_to_int(save_ftp, 10, &value)) {
            return CT_FTP_CTL_INVALID;
        }
        if (value > UINT16_MAX) {
            return CT_FTP_CTL_INVALID;
        }
        port_hs = (uint16_t) value;
    }

    ovs_be16 port = htons(port_hs);
    ovs_be32 conn_ipv4_addr;

    switch (mode) {
    case CT_FTP_MODE_ACTIVE:
        *v4_addr_rep =
            conn_for_expectation->key_node[CT_DIR_REV].key.dst.addr.ipv4;
        conn_ipv4_addr =
            conn_for_expectation->key_node[CT_DIR_FWD].key.src.addr.ipv4;
        break;
    case CT_FTP_MODE_PASSIVE:
        *v4_addr_rep =
            conn_for_expectation->key_node[CT_DIR_FWD].key.dst.addr.ipv4;
        conn_ipv4_addr =
            conn_for_expectation->key_node[CT_DIR_REV].key.src.addr.ipv4;
        break;
    case CT_TFTP_MODE:
    default:
        OVS_NOT_REACHED();
    }

    if (!extended || mode == CT_FTP_MODE_ACTIVE) {
        ovs_be32 ftp_ipv4_addr;
        ftp_ipv4_addr = ip_addr.s_addr;
        /* Although most servers will block this exploit, there may be some
         * less well managed. */
        if (ftp_ipv4_addr != conn_ipv4_addr && ftp_ipv4_addr != *v4_addr_rep) {
            return CT_FTP_CTL_INVALID;
        }
    }

    expectation_create(ct, port, conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
    return CT_FTP_CTL_INTEREST;
}

static char *
skip_ipv6_digits(char *str)
{
    while (isxdigit(*str) || *str == ':' || *str == '.') {
        str++;
    }
    return str;
}

static enum ftp_ctl_pkt
process_ftp_ctl_v6(struct conntrack *ct,
                   struct dp_packet *pkt,
                   const struct conn *conn_for_exp,
                   union ct_addr *v6_addr_rep, char **ftp_data_start,
                   size_t *addr_offset_from_ftp_data_start,
                   size_t *addr_size, enum ct_alg_mode *mode)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    char *tcp_hdr = (char *) th;
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);
    *ftp_data_start = tcp_hdr + tcp_hdr_len;
    char *ftp = ftp_msg;
    struct in6_addr ip6_addr;

    if (!strncasecmp(ftp, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD))) {
        ftp = ftp_msg + strlen(FTP_EPRT_CMD);
        ftp = skip_non_digits(ftp);
        if (*ftp != FTP_AF_V6 || isdigit(ftp[1])) {
            return CT_FTP_CTL_INVALID;
        }
        /* Jump over delimiter. */
        ftp += 2;

        memset(&ip6_addr, 0, sizeof ip6_addr);
        char *ip_addr_start = ftp;
        *addr_offset_from_ftp_data_start = ip_addr_start - ftp_msg;
        ftp = skip_ipv6_digits(ftp);
        *ftp = 0;
        *addr_size = ftp - ip_addr_start;
        int rc2 = inet_pton(AF_INET6, ip_addr_start, &ip6_addr);
        if (rc2 != 1) {
            return CT_FTP_CTL_INVALID;
        }
        ftp++;
        *mode = CT_FTP_MODE_ACTIVE;
    } else {
        ftp = ftp_msg + strcspn(ftp_msg, "(");
        ftp = skip_non_digits(ftp);
        if (!isdigit(*ftp)) {
            return CT_FTP_CTL_INVALID;
        }

        /* Not used for passive mode. */
        *addr_offset_from_ftp_data_start = 0;
        *addr_size = 0;

        *mode = CT_FTP_MODE_PASSIVE;
    }

    char *save_ftp = ftp;
    ftp = terminate_number_str(ftp, MAX_EXT_FTP_PORT_DGTS);
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }

    int value;
    if (!str_to_int(save_ftp, 10, &value)) {
        return CT_FTP_CTL_INVALID;
    }
    if (value > CT_MAX_L4_PORT) {
        return CT_FTP_CTL_INVALID;
    }

    uint16_t port_hs = value;
    ovs_be16 port = htons(port_hs);

    switch (*mode) {
    case CT_FTP_MODE_ACTIVE:
        *v6_addr_rep = conn_for_exp->key_node[CT_DIR_REV].key.dst.addr;
        /* Although most servers will block this exploit, there may be some
         * less well managed. */
        if (memcmp(&ip6_addr, &v6_addr_rep->ipv6, sizeof ip6_addr) &&
            memcmp(&ip6_addr,
                   &conn_for_exp->key_node[CT_DIR_FWD].key.src.addr.ipv6,
                   sizeof ip6_addr)) {
            return CT_FTP_CTL_INVALID;
        }
        break;
    case CT_FTP_MODE_PASSIVE:
        *v6_addr_rep = conn_for_exp->key_node[CT_DIR_FWD].key.dst.addr;
        break;
    case CT_TFTP_MODE:
    default:
        OVS_NOT_REACHED();
    }

    expectation_create(ct, port, conn_for_exp,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
    return CT_FTP_CTL_INTEREST;
}

static int
repl_ftp_v6_addr(struct dp_packet *pkt, union ct_addr v6_addr_rep,
                 char *ftp_data_start,
                 size_t addr_offset_from_ftp_data_start,
                 size_t addr_size, enum ct_alg_mode mode)
{
    /* This is slightly bigger than really possible. */
    enum { MAX_FTP_V6_NAT_DELTA = 45 };

    if (mode == CT_FTP_MODE_PASSIVE) {
        return 0;
    }

    /* Do conservative check for pathological MTU usage. */
    uint32_t orig_used_size = dp_packet_size(pkt);
    if (orig_used_size + MAX_FTP_V6_NAT_DELTA >
        dp_packet_get_allocated(pkt)) {

        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "Unsupported effective MTU %u used with FTP V6",
                     dp_packet_get_allocated(pkt));
        return 0;
    }

    char v6_addr_str[INET6_ADDRSTRLEN] = {0};
    ovs_assert(inet_ntop(AF_INET6, &v6_addr_rep.ipv6, v6_addr_str,
                         sizeof v6_addr_str));
    modify_packet(pkt, ftp_data_start + addr_offset_from_ftp_data_start,
                  addr_size, v6_addr_str, strlen(v6_addr_str),
                  orig_used_size);
    return (int) strlen(v6_addr_str) - (int) addr_size;
}

/* Increment/decrement a TCP sequence number. */
static void
adj_seqnum(ovs_16aligned_be32 *val, int32_t inc)
{
    put_16aligned_be32(val, htonl(ntohl(get_16aligned_be32(val)) + inc));
}

static void
handle_ftp_ctl(struct conntrack *ct, const struct conn_lookup_ctx *ctx,
               struct dp_packet *pkt, struct conn *ec, long long now,
               enum ftp_ctl_pkt ftp_ctl, bool nat)
{
    struct ip_header *l3_hdr = dp_packet_l3(pkt);
    ovs_be32 v4_addr_rep = 0;
    union ct_addr v6_addr_rep;
    size_t addr_offset_from_ftp_data_start = 0;
    size_t addr_size = 0;
    char *ftp_data_start;
    enum ct_alg_mode mode = CT_FTP_MODE_ACTIVE;

    if (detect_ftp_ctl_type(ctx, pkt) != ftp_ctl) {
        return;
    }

    struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
    int64_t seq_skew = 0;

    if (ftp_ctl == CT_FTP_CTL_INTEREST) {
        enum ftp_ctl_pkt rc;
        if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
            rc = process_ftp_ctl_v6(ct, pkt, ec,
                                    &v6_addr_rep, &ftp_data_start,
                                    &addr_offset_from_ftp_data_start,
                                    &addr_size, &mode);
        } else {
            rc = process_ftp_ctl_v4(ct, pkt, ec,
                                    &v4_addr_rep, &ftp_data_start,
                                    &addr_offset_from_ftp_data_start,
                                    &addr_size);
        }
        if (rc == CT_FTP_CTL_INVALID) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_WARN_RL(&rl, "Invalid FTP control packet format");
            pkt->md.ct_state |= CS_TRACKED | CS_INVALID;
            return;
        } else if (rc == CT_FTP_CTL_INTEREST) {
            uint16_t ip_len;

            if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
                if (nat) {
                    seq_skew = repl_ftp_v6_addr(pkt, v6_addr_rep,
                                   ftp_data_start,
                                   addr_offset_from_ftp_data_start,
                                   addr_size, mode);
                }

                if (seq_skew) {
                    ip_len = ntohs(nh6->ip6_ctlun.ip6_un1.ip6_un1_plen) +
                        seq_skew;
                    nh6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(ip_len);
                }
            } else {
                if (nat) {
                    seq_skew = repl_ftp_v4_addr(pkt, v4_addr_rep,
                                   ftp_data_start,
                                   addr_offset_from_ftp_data_start,
                                   addr_size);
                }
                if (seq_skew) {
                    ip_len = ntohs(l3_hdr->ip_tot_len) + seq_skew;
                    if (dp_packet_ip_checksum_valid(pkt)) {
                        dp_packet_ip_checksum_set_partial(pkt);
                    } else {
                        l3_hdr->ip_csum = recalc_csum16(l3_hdr->ip_csum,
                                                        l3_hdr->ip_tot_len,
                                                        htons(ip_len));
                    }
                    l3_hdr->ip_tot_len = htons(ip_len);
                }
            }
        } else {
            OVS_NOT_REACHED();
        }
    }

    struct tcp_header *th = dp_packet_l4(pkt);

    if (nat && ec->seq_skew != 0) {
        ctx->reply != ec->seq_skew_dir ?
            adj_seqnum(&th->tcp_ack, -ec->seq_skew) :
            adj_seqnum(&th->tcp_seq, ec->seq_skew);
    }

    if (dp_packet_l4_checksum_valid(pkt)) {
        dp_packet_l4_checksum_set_partial(pkt);
    } else {
        th->tcp_csum = 0;
        if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
            th->tcp_csum = packet_csum_upperlayer6(nh6, th, ctx->key.nw_proto,
                               dp_packet_l4_size(pkt));
        } else {
            uint32_t tcp_csum = packet_csum_pseudoheader(l3_hdr);
            th->tcp_csum = csum_finish(
                 csum_continue(tcp_csum, th, dp_packet_l4_size(pkt)));
        }
    }

    if (seq_skew) {
        conn_seq_skew_set(ct, ec, now, seq_skew + ec->seq_skew,
                          ctx->reply);
    }
}

/* FTP requires sequence-number tracking to stay in sync with the source of
 * any sequence skew introduced by address/port rewriting.  This hook
 * interleaves handle_ftp_ctl() calls with conn_update_state() depending on
 * packet direction so that the skew accounting is always correct. */
static bool
ftp_conn_update_state_hook(struct conntrack *ct, struct dp_packet *pkt,
                           struct conn_lookup_ctx *ctx, struct conn *conn,
                           const struct nat_action_info_t *nat_action_info,
                           enum ct_alg_ctl_type ct_alg_ctl, long long now,
                           bool *create_new_conn)
{
    if (!is_ftp_ctl(ct_alg_ctl)) {
        return false;
    }

    /* Keep sequence tracking in sync with the source of the sequence skew. */
    ovs_mutex_lock(&conn->lock);
    if (ctx->reply != conn->seq_skew_dir) {
        handle_ftp_ctl(ct, ctx, pkt, conn, now, CT_FTP_CTL_OTHER,
                       !!nat_action_info);
        /* conn_update_state acquires conn->lock for unrelated fields. */
        ovs_mutex_unlock(&conn->lock);
        *create_new_conn = conn_update_state(ct, pkt, ctx, conn, now);
    } else {
        ovs_mutex_unlock(&conn->lock);
        *create_new_conn = conn_update_state(ct, pkt, ctx, conn, now);
        ovs_mutex_lock(&conn->lock);
        if (!*create_new_conn) {
            handle_ftp_ctl(ct, ctx, pkt, conn, now, CT_FTP_CTL_OTHER,
                           !!nat_action_info);
        }
        ovs_mutex_unlock(&conn->lock);
    }
    return true;
}

void
conntrack_ftp_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        conn_update_state_hook_register(CT_HOOK_PRI_NORMAL,
                                        ftp_conn_update_state_hook);
        alg_helpers[CT_ALG_CTL_FTP] = handle_ftp_ctl;
        ovsthread_once_done(&once);
    }
}

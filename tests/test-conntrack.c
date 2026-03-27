/*
 * Copyright (c) 2015, 2017 Nicira, Inc.
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
#include "conntrack.h"
#include "conntrack-private.h"
#include "ct-offload.h"
#include "ct-offload-dummy.h"

#include "dp-packet.h"
#include "fatal-signal.h"
#include "flow.h"
#include "netdev.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "pcap-file.h"
#include "timeval.h"
#include "stopwatch.h"

#define STOPWATCH_CT_EXECUTE_COMMIT "ct-execute-commit"
#define STOPWATCH_CT_EXECUTE_NO_COMMIT "ct-execute-no-commit"
#define STOPWATCH_FLUSH_FULL_ZONE "full-zone"
#define STOPWATCH_FLUSH_EMPTY_ZONE "empty-zone"

static const char payload[] = "50540000000a50540000000908004500001c0000000000"
                              "11a4cd0a0101010a0101020001000200080000";

static struct dp_packet *
build_packet(uint16_t udp_src, uint16_t udp_dst, ovs_be16 *dl_type)
{
    struct udp_header *udp;
    struct flow flow;
    struct dp_packet *pkt = dp_packet_new(sizeof payload / 2);

    dp_packet_put_hex(pkt, payload, NULL);
    flow_extract(pkt, &flow);

    udp = dp_packet_l4(pkt);
    udp->udp_src = htons(udp_src);
    udp->udp_dst = htons(udp_dst);

    *dl_type = flow.dl_type;

    return pkt;
}

/* Build an Ethernet + IPv4 packet.  If 'pkt' is NULL a new buffer is
 * allocated with 64 bytes of extra headroom so the FTP MTU guard passes.
 * The buffer is populated up through the IP header; l4 is set to point
 * directly after the IP header.  The caller is responsible for filling
 * the L4 header and payload that follow. */
static struct dp_packet *
build_eth_ip_packet(struct dp_packet *pkt, struct eth_addr eth_src,
                    struct eth_addr eth_dst, ovs_be32 ip_src, ovs_be32 ip_dst,
                    uint8_t proto, uint16_t payload_alloc)
{
    struct ip_header *iph;
    uint16_t proto_len;

    switch (proto) {
    case IPPROTO_TCP:  proto_len = TCP_HEADER_LEN;  break;
    case IPPROTO_UDP:  proto_len = UDP_HEADER_LEN;  break;
    case IPPROTO_ICMP: proto_len = ICMP_HEADER_LEN; break;
    default:           proto_len = 0;               break;
    }

    if (pkt == NULL) {
        /* 64-byte extra headroom keeps dp_packet_get_allocated() large enough
         * that the FTP V4 MTU guard (orig_used_size + 8 <= allocated) passes
         * even when the packet is near its maximum size. */
        pkt = dp_packet_new_with_headroom(ETH_HEADER_LEN + IP_HEADER_LEN
                                          + proto_len + payload_alloc, 64);
    }

    eth_compose(pkt, eth_src, eth_dst, ETH_TYPE_IP,
                IP_HEADER_LEN + proto_len + payload_alloc);
    iph = dp_packet_l3(pkt);
    iph->ip_ihl_ver = IP_IHL_VER(5, 4);
    iph->ip_tot_len = htons(IP_HEADER_LEN + proto_len + payload_alloc);
    iph->ip_ttl = 64;
    iph->ip_proto = proto;
    packet_set_ipv4_addr(pkt, &iph->ip_src, ip_src);
    packet_set_ipv4_addr(pkt, &iph->ip_dst, ip_dst);
    iph->ip_csum = csum(iph, IP_HEADER_LEN);
    dp_packet_set_l4(pkt, (char *) iph + IP_HEADER_LEN);
    return pkt;
}

/* Fill the TCP header and optional payload for a packet previously built with
 * build_eth_ip_packet().  The 'payload' buffer of 'payload_len' bytes is
 * appended after the TCP header if non-NULL.  IP total-length, IP checksum,
 * and TCP checksum are all updated to reflect the final packet contents. */
static struct dp_packet *
build_tcp_packet(struct dp_packet *pkt, uint16_t tcp_src, uint16_t tcp_dst,
                 uint16_t tcp_flags, const char *tcp_payload,
                 size_t payload_len)
{
    struct tcp_header *tcph;
    struct ip_header *iph;
    uint16_t ip_tot_len;
    uint32_t tcp_csum;
    struct flow flow;

    ovs_assert(pkt);
    tcph = dp_packet_l4(pkt);
    ovs_assert(tcph);

    tcph->tcp_src = htons(tcp_src);
    tcph->tcp_dst = htons(tcp_dst);
    put_16aligned_be32(&tcph->tcp_seq, 0);
    put_16aligned_be32(&tcph->tcp_ack, 0);
    tcph->tcp_ctl = TCP_CTL(tcp_flags, TCP_HEADER_LEN / 4);
    tcph->tcp_winsz = htons(65535);
    tcph->tcp_csum = 0;
    tcph->tcp_urg = 0;

    if (tcp_payload && payload_len > 0) {
        /* The caller must have pre-allocated space via build_eth_ip_packet's
         * payload_alloc argument.  Write directly to avoid a realloc that
         * would lose the extra headroom required by the FTP MTU guard. */
        memcpy((char *) tcph + TCP_HEADER_LEN, tcp_payload, payload_len);
    }

    /* Update IP total length and recompute IP checksum. */
    iph = dp_packet_l3(pkt);
    ip_tot_len = IP_HEADER_LEN + TCP_HEADER_LEN + payload_len;
    iph->ip_tot_len = htons(ip_tot_len);
    iph->ip_csum = 0;
    iph->ip_csum = csum(iph, IP_HEADER_LEN);

    /* Compute TCP checksum over pseudo-header + TCP segment. */
    tcp_csum = packet_csum_pseudoheader(iph);
    tcph->tcp_csum = csum_finish(
        csum_continue(tcp_csum, tcph, TCP_HEADER_LEN + payload_len));

    /* Set l3/l4 offsets so conntrack can extract a flow key. */
    flow_extract(pkt, &flow);
    return pkt;
}

static struct dp_packet_batch *
prepare_packets(size_t n, bool change, unsigned tid, ovs_be16 *dl_type)
{
    struct dp_packet_batch *pkt_batch = xzalloc(sizeof *pkt_batch);
    size_t i;

    ovs_assert(n <= ARRAY_SIZE(pkt_batch->packets));

    dp_packet_batch_init(pkt_batch);
    for (i = 0; i < n; i++) {
        uint16_t udp_dst = change ? 2+1 : 2;
        struct dp_packet *pkt = build_packet(1 + tid, udp_dst, dl_type);
        dp_packet_batch_add(pkt_batch, pkt);
    }

    return pkt_batch;
}

static void
destroy_packets(struct dp_packet_batch *pkt_batch)
{
    dp_packet_delete_batch(pkt_batch, true);
    free(pkt_batch);
}

struct thread_aux {
    pthread_t thread;
    unsigned tid;
};

static struct conntrack *ct;
static unsigned long n_threads, n_pkts, batch_size;
static bool change_conn = false;
static struct ovs_barrier barrier;

static void *
ct_thread_main(void *aux_)
{
    struct thread_aux *aux = aux_;
    struct dp_packet_batch *pkt_batch;
    struct dp_packet *pkt;
    ovs_be16 dl_type;
    size_t i;
    long long now = time_msec();

    pkt_batch = prepare_packets(batch_size, change_conn, aux->tid, &dl_type);
    ovs_barrier_block(&barrier);
    for (i = 0; i < n_pkts; i += batch_size) {
        conntrack_execute(ct, pkt_batch, dl_type, false, true, 0, NULL, NULL,
                          NULL, NULL, now, 0, NULL);
        DP_PACKET_BATCH_FOR_EACH (j, pkt, pkt_batch) {
            pkt_metadata_init_conn(&pkt->md);
        }
    }
    ovs_barrier_block(&barrier);
    destroy_packets(pkt_batch);

    return NULL;
}

static void
test_benchmark(struct ovs_cmdl_context *ctx)
{
    struct thread_aux *threads;
    long long start;
    unsigned i;

    fatal_signal_init();

    /* Parse arguments */
    n_threads = strtoul(ctx->argv[1], NULL, 0);
    if (!n_threads) {
        ovs_fatal(0, "n_threads must be at least one");
    }
    n_pkts = strtoul(ctx->argv[2], NULL, 0);
    batch_size = strtoul(ctx->argv[3], NULL, 0);
    if (batch_size == 0 || batch_size > NETDEV_MAX_BURST) {
        ovs_fatal(0, "batch_size must be between 1 and NETDEV_MAX_BURST(%u)",
                  NETDEV_MAX_BURST);
    }
    if (ctx->argc > 4) {
        change_conn = strtoul(ctx->argv[4], NULL, 0);
    }

    threads = xcalloc(n_threads, sizeof *threads);
    ovs_barrier_init(&barrier, n_threads + 1);
    ct = conntrack_init();

    /* Create threads */
    for (i = 0; i < n_threads; i++) {
        threads[i].tid = i;
        threads[i].thread = ovs_thread_create("ct_thread", ct_thread_main,
                                              &threads[i]);
    }
    /* Starts the work inside the threads */
    ovs_barrier_block(&barrier);
    start = time_msec();

    /* Wait for the threads to finish the work */
    ovs_barrier_block(&barrier);
    printf("conntrack:  %5lld ms\n", time_msec() - start);

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i].thread, NULL);
    }

    conntrack_destroy(ct);
    ovs_barrier_destroy(&barrier);
    free(threads);
}

static void
test_benchmark_zones(struct ovs_cmdl_context *ctx)
{
    unsigned long n_conns, n_zones, iterations;
    long long start;
    unsigned i, j;
    ovs_be16 dl_type;
    long long now = time_msec();

    fatal_signal_init();

    /* Parse arguments */
    n_conns = strtoul(ctx->argv[1], NULL, 0);
    if (n_conns == 0 || n_conns >= UINT32_MAX) {
        ovs_fatal(0, "n_conns must be between 1 and 2^32");
    }
    n_zones = strtoul(ctx->argv[2], NULL, 0);
    if (n_zones == 0 || n_zones >= UINT16_MAX) {
        ovs_fatal(0, "n_zones must be between 1 and 2^16");
    }
    iterations = strtoul(ctx->argv[3], NULL, 0);
    if (iterations == 0) {
        ovs_fatal(0, "iterations must be greater than 0");
    }

    ct = conntrack_init();

    /* Create initial connection entries */
    start = time_msec();
    struct dp_packet_batch **pkt_batch = xzalloc(n_conns * sizeof *pkt_batch);
    for (i = 0; i < n_conns; i++) {
        pkt_batch[i] = xzalloc(sizeof(struct dp_packet_batch));
        dp_packet_batch_init(pkt_batch[i]);
        uint16_t udp_src = (i & 0xFFFF0000) >> 16;
        if (udp_src == 0) {
            udp_src = UINT16_MAX;
        }
        uint16_t udp_dst = i & 0xFFFF;
        if (udp_dst == 0) {
            udp_dst = UINT16_MAX;
        }
        struct dp_packet *pkt = build_packet(udp_src, udp_dst, &dl_type);
        dp_packet_batch_add(pkt_batch[i], pkt);
    }
    printf("initial packet generation time: %lld ms\n", time_msec() - start);

    /* Put initial entries to each zone */
    start = time_msec();
    for (i = 0; i < n_zones; i++) {
        for (j = 0; j < n_conns; j++) {
            conntrack_execute(ct, pkt_batch[j], dl_type, false, true, i,
                              NULL, NULL, NULL, NULL, now, 0, NULL);
            pkt_metadata_init_conn(&pkt_batch[j]->packets[0]->md);
        }
    }
    printf("initial insert time: %lld ms\n", time_msec() - start);

    /* Actually run the tests */
    stopwatch_create(STOPWATCH_CT_EXECUTE_COMMIT, SW_US);
    stopwatch_create(STOPWATCH_CT_EXECUTE_NO_COMMIT, SW_US);
    stopwatch_create(STOPWATCH_FLUSH_FULL_ZONE, SW_US);
    stopwatch_create(STOPWATCH_FLUSH_EMPTY_ZONE, SW_US);
    start = time_msec();
    for (i = 0; i < iterations; i++) {
        /* Testing flushing a full zone */
        stopwatch_start(STOPWATCH_FLUSH_FULL_ZONE, time_usec());
        uint16_t zone = 1;
        conntrack_flush(ct, &zone);
        stopwatch_stop(STOPWATCH_FLUSH_FULL_ZONE, time_usec());

        /* Now fill the zone again */
        stopwatch_start(STOPWATCH_CT_EXECUTE_COMMIT, time_usec());
        for (j = 0; j < n_conns; j++) {
            conntrack_execute(ct, pkt_batch[j], dl_type, false, true, zone,
                              NULL, NULL, NULL, NULL, now, 0, NULL);
            pkt_metadata_init_conn(&pkt_batch[j]->packets[0]->md);
        }
        stopwatch_stop(STOPWATCH_CT_EXECUTE_COMMIT, time_usec());

        /* Running conntrack_execute on the now existing connections  */
        stopwatch_start(STOPWATCH_CT_EXECUTE_NO_COMMIT, time_usec());
        for (j = 0; j < n_conns; j++) {
            conntrack_execute(ct, pkt_batch[j], dl_type, false, false, zone,
                              NULL, NULL, NULL, NULL, now, 0, NULL);
            pkt_metadata_init_conn(&pkt_batch[j]->packets[0]->md);
        }
        stopwatch_stop(STOPWATCH_CT_EXECUTE_NO_COMMIT, time_usec());

        /* Testing flushing an empty zone */
        stopwatch_start(STOPWATCH_FLUSH_EMPTY_ZONE, time_usec());
        zone = UINT16_MAX;
        conntrack_flush(ct, &zone);
        stopwatch_stop(STOPWATCH_FLUSH_EMPTY_ZONE, time_usec());
    }

    printf("flush run time: %lld ms\n", time_msec() - start);

    stopwatch_sync();
    struct stopwatch_stats stats_ct_execute_commit = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_CT_EXECUTE_COMMIT, &stats_ct_execute_commit);
    struct stopwatch_stats stats_ct_execute_nocommit = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_CT_EXECUTE_NO_COMMIT,
            &stats_ct_execute_nocommit);
    struct stopwatch_stats stats_flush_full = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_FLUSH_FULL_ZONE, &stats_flush_full);
    struct stopwatch_stats stats_flush_empty = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_FLUSH_EMPTY_ZONE, &stats_flush_empty);

    printf("results:\n");
    printf("         | ct execute (commit) | ct execute (no commit) |"
            " flush full zone | flush empty zone |\n");
    printf("+--------+---------------------+------------------------+"
            "-----------------+------------------+\n");
    printf("| Min    | %16llu us | %19llu us | %12llu us | %13llu us |\n",
            stats_ct_execute_commit.min, stats_ct_execute_nocommit.min,
            stats_flush_full.min, stats_flush_empty.min);
    printf("| Max    | %16llu us | %19llu us | %12llu us | %13llu us |\n",
            stats_ct_execute_commit.max, stats_ct_execute_nocommit.max,
            stats_flush_full.max, stats_flush_empty.max);
    printf("| 95%%ile | %16.2f us | %19.2f us | %12.2f us | %13.2f us |\n",
            stats_ct_execute_commit.pctl_95, stats_ct_execute_nocommit.pctl_95,
            stats_flush_full.pctl_95, stats_flush_empty.pctl_95);
    printf("| Avg    | %16.2f us | %19.2f us | %12.2f us | %13.2f us |\n",
            stats_ct_execute_commit.ewma_1, stats_ct_execute_nocommit.ewma_1,
            stats_flush_full.ewma_1, stats_flush_empty.ewma_1);

    conntrack_destroy(ct);
    for (i = 0; i < n_conns; i++) {
        dp_packet_delete_batch(pkt_batch[i], true);
        free(pkt_batch[i]);
    }
    free(pkt_batch);
}

static void
pcap_batch_execute_conntrack(struct conntrack *ct_,
                             struct dp_packet_batch *pkt_batch)
{
    struct dp_packet_batch new_batch;
    ovs_be16 dl_type = htons(0);
    long long now = time_msec();

    dp_packet_batch_init(&new_batch);

    /* pkt_batch contains packets with different 'dl_type'. We have to
     * call conntrack_execute() on packets with the same 'dl_type'. */
    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH (i, packet, pkt_batch) {
        struct flow flow;

        /* This also initializes the l3 and l4 pointers. */
        flow_extract(packet, &flow);

        if (dp_packet_batch_is_empty(&new_batch)) {
            dl_type = flow.dl_type;
        }

        if (flow.dl_type != dl_type) {
            conntrack_execute(ct_, &new_batch, dl_type, false, true, 0,
                              NULL, NULL, NULL, NULL, now, 0, NULL);
            dp_packet_batch_init(&new_batch);
        }
        dp_packet_batch_add(&new_batch, packet);
    }

    if (!dp_packet_batch_is_empty(&new_batch)) {
        conntrack_execute(ct_, &new_batch, dl_type, false, true, 0, NULL, NULL,
                          NULL, NULL, now, 0, NULL);
    }

}

static void
test_pcap(struct ovs_cmdl_context *ctx)
{
    size_t total_count, batch_size_;
    struct pcap_file *pcap;
    int err = 0;

    pcap = ovs_pcap_open(ctx->argv[1], "rb");
    if (!pcap) {
        return;
    }

    batch_size_ = 1;
    if (ctx->argc > 2) {
        batch_size_ = strtoul(ctx->argv[2], NULL, 0);
        if (batch_size_ == 0 || batch_size_ > NETDEV_MAX_BURST) {
            ovs_fatal(0,
                      "batch_size must be between 1 and NETDEV_MAX_BURST(%u)",
                      NETDEV_MAX_BURST);
        }
    }

    fatal_signal_init();

    ct = conntrack_init();
    total_count = 0;
    for (;;) {
        struct dp_packet *packet;
        struct dp_packet_batch pkt_batch_;
        struct dp_packet_batch *batch = &pkt_batch_;

        dp_packet_batch_init(batch);
        for (int i = 0; i < batch_size_; i++) {
            err = ovs_pcap_read(pcap, &packet, NULL);
            if (err) {
                break;
            }
            dp_packet_batch_add(batch, packet);
        }
        if (dp_packet_batch_is_empty(batch)) {
            break;
        }
        pcap_batch_execute_conntrack(ct, batch);

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            struct ds ds = DS_EMPTY_INITIALIZER;

            total_count++;

            format_flags(&ds, ct_state_to_string, packet->md.ct_state, '|');
            printf("%"PRIuSIZE": %s\n", total_count, ds_cstr(&ds));

            ds_destroy(&ds);
        }

        dp_packet_delete_batch(batch, true);
    }
    conntrack_destroy(ct);
    ovs_pcap_close(pcap);
}

/* Conntrack functional testing. */

/* FTP IPv4 PORT payload for testing. */
#define FTP_PORT_CMD_STR  "PORT 192,168,123,2,113,42\r\n"
#define FTP_CMD_PAD       234
#define FTP_PAYLOAD_LEN   (sizeof FTP_PORT_CMD_STR - 1 + FTP_CMD_PAD)

/* Test modify_packet wrapping.
 *
 * The test builds a minimal FTP control-channel exchange:
 *   1. A TCP SYN that creates a conntrack entry with helper=ftp and SNAT.
 *   2. A PSH|ACK carrying "PORT 192,168,123,2,113,42\r\n" padded to exactly
 *      261 bytes of TCP payload, which makes total_size == 256.
 *
 * After the PORT packet is processed the address field in the payload must
 * read "192,168,1,1" (the SNAT address with dots replaced by commas). */
static void
test_ftp_alg_large_payload(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Packet endpoints. */
    struct eth_addr eth_src = ETH_ADDR_C(00, 01, 02, 03, 04, 05);
    struct eth_addr eth_dst = ETH_ADDR_C(00, 06, 07, 08, 09, 0a);
    ovs_be32 ip_src = inet_addr("192.168.123.2"); /* FTP client. */
    ovs_be32 ip_dst = inet_addr("192.168.1.1");   /* FTP server / SNAT addr. */
    uint16_t sport = 12345;
    uint16_t dport = 21;                          /* FTP control port. */

    /* SNAT: rewrite client address to 192.168.1.1 in PORT commands. */
    struct nat_action_info_t nat_info;
    memset(&nat_info, 0, sizeof nat_info);
    nat_info.nat_action = NAT_ACTION_SRC;
    nat_info.min_addr.ipv4 = ip_dst;
    nat_info.max_addr.ipv4 = ip_dst;

    ct = conntrack_init();
    conntrack_set_tcp_seq_chk(ct, false);

    long long now = time_msec();

    struct dp_packet *syn = build_eth_ip_packet(NULL, eth_src, eth_dst,
                                                ip_src, ip_dst,
                                                IPPROTO_TCP, 0);
    build_tcp_packet(syn, sport, dport, TCP_SYN, NULL, 0);

    struct dp_packet_batch syn_batch;
    dp_packet_batch_init_packet(&syn_batch, syn);
    conntrack_execute(ct, &syn_batch, htons(ETH_TYPE_IP), false, true, 0,
                      NULL, NULL, "ftp", &nat_info, now, 0, NULL);
    dp_packet_delete_batch(&syn_batch, true);

    /* We get to skip some of the processing because the conntrack execute
     * above will create the required conntrack entries. */

    /* Build the large payload: PORT command followed by padding spaces
     * and a final "\r\n" to reach exactly FTP_PAYLOAD_LEN bytes.  The
     * FTP parser only looks at the first LARGEST_FTP_MSG_OF_INTEREST (128)
     * bytes, so the trailing spaces do not interfere with parsing. */
    char ftp_payload[FTP_PAYLOAD_LEN];
    memcpy(ftp_payload, FTP_PORT_CMD_STR, sizeof FTP_PORT_CMD_STR - 1);
    memset(ftp_payload + sizeof FTP_PORT_CMD_STR - 1, ' ', FTP_CMD_PAD);

    struct dp_packet *port_pkt =
        build_eth_ip_packet(NULL, eth_src, eth_dst, ip_src, ip_dst,
                            IPPROTO_TCP, FTP_PAYLOAD_LEN);
    build_tcp_packet(port_pkt, sport, dport, TCP_PSH | TCP_ACK,
                     ftp_payload, FTP_PAYLOAD_LEN);

    struct dp_packet_batch port_batch;
    dp_packet_batch_init_packet(&port_batch, port_pkt);
    conntrack_execute(ct, &port_batch, htons(ETH_TYPE_IP), false, true, 0,
                      NULL, NULL, "ftp", &nat_info, now, 0, NULL);

    struct tcp_header *th = dp_packet_l4(port_pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    const char *ftp_start = (const char *) th + tcp_hdr_len;
    ovs_assert(!strncmp(ftp_start, "PORT 192,168,1,1,", 17));
    dp_packet_delete_batch(&port_batch, true);
    conntrack_destroy(ct);
}

/* Verify that conn_private_id_alloc() returns a valid slot ID and that the
 * idiomatic "store the ID in a static variable at module init" pattern works.
 */
static void
test_private_id_alloc(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Mirrors the real-world pattern: a module stores its slot ID in a static
     * so it is initialised once and available everywhere in the translation
     * unit. */
    static ct_private_id_t my_id = CT_PRIVATE_ID_INVALID;

    my_id = conn_private_id_alloc(NULL);

    ovs_assert(my_id != CT_PRIVATE_ID_INVALID);

    ovs_assert(my_id < CT_CONN_PRIVATE_MAX);

    /* The first allocation must yield slot 0. */
    ovs_assert(my_id == 0);
    printf(".\n");
}

/* Allocate every available slot and confirm that the next request returns
 * CT_PRIVATE_ID_INVALID.  Each successful allocation prints one dot so the
 * .at test can verify both the count and the error behaviour.
 */
static void
test_private_id_exhaustion(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ct_private_id_t ids[CT_CONN_PRIVATE_MAX];

    /* Fill all CT_CONN_PRIVATE_MAX slots. */
    for (unsigned int i = 0; i < CT_CONN_PRIVATE_MAX; i++) {
        ids[i] = conn_private_id_alloc(NULL);
        ovs_assert(ids[i] != CT_PRIVATE_ID_INVALID);

        ovs_assert(ids[i] == i);
        printf(".");
    }

    /* The very next allocation must fail. */
    ct_private_id_t extra = conn_private_id_alloc(NULL);
    ovs_assert(extra == CT_PRIVATE_ID_INVALID);
    printf(".\n");
}

/* Globals written by the destructor callback used in test 3. */
static int   dtor_call_count = 0;
static void *dtor_last_ptr   = NULL;

static void
record_destructor(void *data)
{
    dtor_call_count++;
    dtor_last_ptr = data;
}

/* Register a destructor, commit a real connection, attach a sentinel pointer
 * as private data, then destroy the conntrack instance.  After draining the
 * RCU queue (ovsrcu_exit) the destructor must have been called exactly
 * once with the sentinel value.
 */
static uintptr_t ERRPTR;

static void
test_private_destructor(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Sentinel: a non-NULL pointer value we can identify unambiguously.
     * ERRPTR is defined above in case we want to use it in the future as
     * a platform-agnostic and portable sentinel value rather than some
     * hardcoded hex. */
    void *sentinel = (void *)(uintptr_t)&ERRPTR;

    static ct_private_id_t dtor_id = CT_PRIVATE_ID_INVALID;
    dtor_id = conn_private_id_alloc(record_destructor);
    ovs_assert(dtor_id != CT_PRIVATE_ID_INVALID);

    /* Create a conntrack instance and commit one UDP connection. */
    struct conntrack *lct = conntrack_init();
    ovs_be16 dl_type;
    struct dp_packet *pkt = build_packet(1, 2, &dl_type);
    struct dp_packet_batch batch;
    dp_packet_batch_init(&batch);
    dp_packet_batch_add(&batch, pkt);

    long long now = time_msec();
    conntrack_execute(lct, &batch, dl_type, false, true, 0,
                      NULL, NULL, NULL, NULL, now, 0, NULL);

    /* After a committed execute the packet carries a cached conn pointer. */
    struct conn *conn = pkt->md.conn;
    ovs_assert(conn != NULL);

    /* Attach the sentinel as private data for our slot. */
    ovs_mutex_lock(&conn->lock);
    conn_private_set(conn, dtor_id, sentinel);
    ovs_mutex_unlock(&conn->lock);

    /* Destroying the tracker flushes all connections, queuing delete_conn()
     * callbacks via ovsrcu_postpone().  The destructor fires once those
     * callbacks are processed. */
    conntrack_destroy(lct);

    /* ovsrcu_exit() stops the urcu background thread and synchronously drains
     * all pending postponed callbacks (including delete_conn__ / destructor
     * chain) before returning.  ovsrcu_synchronize() is insufficient here: it
     * only waits for threads to quiesce, not for the urcu thread to have
     * actually executed the queued callbacks. */
    ovsrcu_exit();

    ovs_assert(dtor_call_count == 1);

    ovs_assert(dtor_last_ptr == sentinel);

    dp_packet_delete_batch(&batch, true);
    printf(".\n");
}


/* ===========================================================================
 * CT offload dummy provider tests
 *
 * These tests exercise the ct_offload provider API directly without going
 * through conntrack_execute.  The offload global-enable flag is deliberately
 * not set here: the unit tests own the provider list and call the API
 * functions directly.  End-to-end enablement (hw-offload=true via DB config)
 * is covered by the dpif-netdev integration test.
 *
 * Each test must be run as a separate ovstest invocation so that the
 * process-global provider list starts empty.
 * ===========================================================================
 */

/* The dummy only compares pointer addresses and never dereferences them, so a
 * small integer cast is sufficient. */
#define FAKE_CONN(n)   ((struct conn *)(uintptr_t)(n))
#define FAKE_NETDEV(n) ((struct netdev *)(uintptr_t)(n))

/* Test: offload-conn-add
 * ----------------------
 * Register the dummy provider, call ct_offload_conn_add() directly, and
 * verify that the conn_add hook was invoked and the connection is tracked.
 */
static void
test_offload_conn_add(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ct_offload_force_enable(true);
    ct_offload_dummy_register();

    struct conn *fake = FAKE_CONN(1);
    struct ct_offload_ctx offload_ctx = {
        .conn = fake, .netdev_in = NULL,
    };
    ct_offload_conn_add(&offload_ctx);

    ovs_assert(ct_offload_dummy_n_added() == 1);
    ovs_assert(ct_offload_dummy_contains(fake));

    ct_offload_dummy_unregister();
    ct_offload_force_enable(false);
    printf(".\n");
}

/* Test: offload-conn-del
 * ----------------------
 * Register the dummy, add then delete a connection via the API, and verify
 * that conn_del was called and the connection is no longer tracked.
 */
static void
test_offload_conn_del(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ct_offload_force_enable(true);
    ct_offload_dummy_register();

    struct conn *fake = FAKE_CONN(1);
    struct ct_offload_ctx offload_ctx = {
        .conn = fake, .netdev_in = NULL,
    };

    ct_offload_conn_add(&offload_ctx);
    ovs_assert(ct_offload_dummy_n_added() == 1);

    ct_offload_conn_del(&offload_ctx);
    ovs_assert(ct_offload_dummy_n_deleted() == 1);
    ovs_assert(!ct_offload_dummy_contains(fake));

    ct_offload_dummy_unregister();
    ct_offload_force_enable(false);
    printf(".\n");
}

/* Test: offload-conn-update
 * -------------------------
 * Register the dummy, add a connection, call ct_offload_conn_update()
 * directly, and verify that a non-zero last-used timestamp is returned.
 */
static void
test_offload_conn_update(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ct_offload_force_enable(true);
    ct_offload_dummy_register();

    struct conn *fake = FAKE_CONN(1);
    struct ct_offload_ctx offload_ctx = {
        .conn = fake, .netdev_in = NULL,
    };

    ct_offload_conn_add(&offload_ctx);

    long long ts = ct_offload_conn_update(&offload_ctx);
    ovs_assert(ts != 0);
    ovs_assert(ct_offload_dummy_n_updated() == 1);

    ct_offload_dummy_unregister();
    ct_offload_force_enable(false);
    printf(".\n");
}

/* Test: offload-multi-conn
 * ------------------------
 * Register the dummy, add N connections via the API, and verify that each
 * is tracked independently.
 */
#define OFFLOAD_MULTI_N 4

static void
test_offload_multi_conn(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ct_offload_force_enable(true);
    ct_offload_dummy_register();

    for (unsigned i = 1; i <= OFFLOAD_MULTI_N; i++) {
        struct ct_offload_ctx offload_ctx = {
            .conn = FAKE_CONN(i), .netdev_in = NULL,
        };
        ct_offload_conn_add(&offload_ctx);
    }

    ovs_assert(ct_offload_dummy_n_added() == OFFLOAD_MULTI_N);
    for (unsigned i = 1; i <= OFFLOAD_MULTI_N; i++) {
        ovs_assert(ct_offload_dummy_contains(FAKE_CONN(i)));
    }

    ct_offload_dummy_unregister();
    ct_offload_force_enable(false);
    printf(".\n");
}

/* Test: offload-conn-established
 * --------------------------------
 * Drive a TCP three-way handshake through conntrack_execute() with the dummy
 * offload provider registered.  Verifies three properties:
 *
 *  (a) conn_add fires on the SYN (new connection created, forward netdev
 *      recorded); conn_established does NOT fire yet.
 *  (b) conn_established fires exactly once on the first ESTABLISHED reply
 *      (SYN-ACK), recording the reply-direction netdev so that the dummy
 *      entry is fully bidirectional.
 *  (c) A subsequent reply packet (ACK) does NOT cause a second
 *      conn_established call the "exactly once" guarantee holds.
 *
 * ct_offload_dummy_register() calls ct_offload_force_enable(true), which
 * makes ct_offload_enabled() return true so the guards in conntrack.c fire
 * without a real hardware offload backend.
 */
static void
test_offload_conn_established(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Allocate the per-connection private slot before registering so that the
     * ADD/ESTABLISHED state transitions are tracked in conn->private[].
     * The simple FAKE_CONN tests skip this step because they do not exercise
     * the private-slot code path. */
    ct_offload_alloc_private_slot();
    ct_offload_force_enable(true);
    ct_offload_dummy_register();

    struct conntrack *lct = conntrack_init();
    /* Disable TCP sequence-number checking so test packets with seq=0 are
     * accepted by the state machine. */
    conntrack_set_tcp_seq_chk(lct, false);

    long long now = time_msec();

    struct eth_addr eth_a = ETH_ADDR_C(00, 00, 00, 00, 00, 01);
    struct eth_addr eth_b = ETH_ADDR_C(00, 00, 00, 00, 00, 02);
    ovs_be32 ip_a = inet_addr("10.0.0.1");
    ovs_be32 ip_b = inet_addr("10.0.0.2");
    uint16_t sport = 1234;
    uint16_t dport = 80;

    /* --- (a) SYN: forward direction, creates the connection entry. --- */
    struct dp_packet *syn = build_eth_ip_packet(NULL, eth_a, eth_b,
                                                ip_a, ip_b,
                                                IPPROTO_TCP, 0);
    build_tcp_packet(syn, sport, dport, TCP_SYN, NULL, 0);

    struct dp_packet_batch syn_batch;
    dp_packet_batch_init_packet(&syn_batch, syn);
    conntrack_execute(lct, &syn_batch, htons(ETH_TYPE_IP), false, true, 0,
                      NULL, NULL, NULL, NULL, now, 0, FAKE_NETDEV(1));

    /* conn_add must have fired; conn_established must not have. */
    ovs_assert(ct_offload_dummy_n_added() == 1);
    ovs_assert(ct_offload_dummy_n_established() == 0);

    /* The packet carries the conn pointer after commit. */
    struct conn *conn = syn->md.conn;
    ovs_assert(conn != NULL);
    ovs_assert(ct_offload_conn_is_offloaded(conn));
    ovs_assert(!ct_offload_conn_is_established(conn));

    dp_packet_delete_batch(&syn_batch, true);

    /* --- (b) SYN-ACK: reply direction, transitions to ESTABLISHED. --- */
    struct dp_packet *synack = build_eth_ip_packet(NULL, eth_b, eth_a,
                                                   ip_b, ip_a,
                                                   IPPROTO_TCP, 0);
    build_tcp_packet(synack, dport, sport, TCP_SYN | TCP_ACK, NULL, 0);

    struct dp_packet_batch synack_batch;
    dp_packet_batch_init_packet(&synack_batch, synack);
    conntrack_execute(lct, &synack_batch, htons(ETH_TYPE_IP), false, true, 0,
                      NULL, NULL, NULL, NULL, now, 0, FAKE_NETDEV(2));

    /* conn_established fires exactly once on the first ESTABLISHED reply. */
    ovs_assert(ct_offload_dummy_n_established() == 1);
    ovs_assert(ct_offload_conn_is_established(conn));
    /* Both netdev pointers are now known: the entry is fully bidirectional. */
    ovs_assert(ct_offload_dummy_is_bidirectional(conn));

    dp_packet_delete_batch(&synack_batch, true);

    /* --- (c) ACK: another reply packet must NOT trigger conn_established
     *             again.  The private-slot guard enforces this. --- */
    struct dp_packet *ack = build_eth_ip_packet(NULL, eth_b, eth_a,
                                                ip_b, ip_a,
                                                IPPROTO_TCP, 0);
    build_tcp_packet(ack, dport, sport, TCP_ACK, NULL, 0);

    struct dp_packet_batch ack_batch;
    dp_packet_batch_init_packet(&ack_batch, ack);
    conntrack_execute(lct, &ack_batch, htons(ETH_TYPE_IP), false, true, 0,
                      NULL, NULL, NULL, NULL, now, 0, FAKE_NETDEV(2));

    /* Counter must still be 1 - conn_established must not have fired again. */
    ovs_assert(ct_offload_dummy_n_established() == 1);

    dp_packet_delete_batch(&ack_batch, true);

    conntrack_destroy(lct);
    ct_offload_dummy_unregister();
    ct_offload_force_enable(false);
    printf(".\n");
}

/* Test: offload-conn-established-api
 * ------------------------------------
 * Exercise ct_offload_conn_established() directly (not through
 * conntrack_execute) to verify that the "exactly once" guarantee in the
 * dispatch layer holds independently of the conntrack state machine.
 *
 * Sequence:
 *   1. conn_add() - transitions the private slot to CT_OFFLOAD_STATE_ADDED.
 *   2. conn_established() - should dispatch to the provider exactly once and
 *      advance the slot to CT_OFFLOAD_STATE_EST.
 *   3. A second conn_established() call with the same conn must be a no-op
 *      (provider not called again, counter unchanged).
 */
static void
test_offload_conn_established_api(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ct_offload_alloc_private_slot();
    ct_offload_force_enable(true);
    ct_offload_dummy_register();

    /* We need a real conn with a live private-data slot, so spin up a minimal
     * conntrack instance and commit one UDP packet to get a conn. */
    struct conntrack *lct = conntrack_init();
    long long now = time_msec();

    ovs_be16 dl_type;
    struct dp_packet *pkt = build_packet(1, 2, &dl_type);
    struct dp_packet_batch batch;
    dp_packet_batch_init_packet(&batch, pkt);
    conntrack_execute(lct, &batch, dl_type, false, true, 0,
                      NULL, NULL, NULL, NULL, now, 0, FAKE_NETDEV(1));
    struct conn *conn = pkt->md.conn;
    ovs_assert(conn != NULL);
    dp_packet_delete_batch(&batch, true);

    /* conn_add should have fired (via conntrack_execute). */
    ovs_assert(ct_offload_dummy_n_added() == 1);
    ovs_assert(ct_offload_dummy_n_established() == 0);
    ovs_assert(ct_offload_conn_is_offloaded(conn));
    ovs_assert(!ct_offload_conn_is_established(conn));

    /* First call: must dispatch to the provider. */
    struct ct_offload_ctx ctx1 = {
        .conn = conn, .netdev_in = FAKE_NETDEV(2),
    };
    ct_offload_conn_established(&ctx1);
    ovs_assert(ct_offload_dummy_n_established() == 1);
    ovs_assert(ct_offload_conn_is_established(conn));
    ovs_assert(ct_offload_dummy_is_bidirectional(conn));

    /* Second call with the same conn: must be a no-op. */
    ct_offload_conn_established(&ctx1);

    ovs_assert(ct_offload_dummy_n_established() == 1);  /* unchanged */

    conntrack_destroy(lct);
    ct_offload_dummy_unregister();
    ct_offload_force_enable(false);
    printf(".\n");
}


static const struct ovs_cmdl_command commands[] = {
    /* Connection tracker tests. */
    /* Starts 'n_threads' threads. Each thread will send 'n_pkts' packets to
     * the connection tracker, 'batch_size' per call. If 'change_connection'
     * is '1', each packet in a batch will have a different source and
     * destination port */
    {"benchmark", "n_threads n_pkts batch_size [change_connection]", 3, 4,
     test_benchmark, OVS_RO},
    /* Reads packets from 'file' and sends them to the connection tracker,
     * 'batch_size' (1 by default) per call, with the commit flag set.
     * Prints the ct_state of each packet. */
    {"pcap", "file [batch_size]", 1, 2, test_pcap, OVS_RO},
    /* Creates 'n_conns' connections in 'n_zones' zones each.
     * Afterwards triggers flush requests repeadeatly for the last filled zone
     * and an empty zone. */
    {"benchmark-zones", "n_conns n_zones iterations", 3, 3,
        test_benchmark_zones, OVS_RO},
    /* Verifies that the FTP ALG replace_substring function correctly handles
     * a packet whose payload puts total_size at exactly 256 bytes.  The
     * original uint8_t parameter type truncated 256 to 0, leading to a
     * near-SIZE_MAX memmove (heap overflow).  The test confirms the address
     * is rewritten to the SNAT target rather than causing a crash. */
    {"ftp-alg-large-payload", "", 0, 0,
        test_ftp_alg_large_payload, OVS_RO},
    /* Private per-connection storage registry tests.
     * Each MUST be run as a separate ovstest invocation so the process-global
     * slot counter is fresh (starts at 0). */
    {"private-id-alloc", "", 0, 0,
     test_private_id_alloc, OVS_RO},
    {"private-id-exhaustion", "", 0, 0,
     test_private_id_exhaustion, OVS_RO},
    {"private-destructor", "", 0, 0,
     test_private_destructor, OVS_RO},
    /* CT offload dummy provider tests.
     * Each must be run as a separate ovstest invocation. */
    {"offload-conn-add", "", 0, 0,
     test_offload_conn_add, OVS_RO},
    {"offload-conn-del", "", 0, 0,
     test_offload_conn_del, OVS_RO},
    {"offload-conn-update", "", 0, 0,
     test_offload_conn_update, OVS_RO},
    {"offload-multi-conn", "", 0, 0,
     test_offload_multi_conn, OVS_RO},
    {"offload-conn-established", "", 0, 0,
     test_offload_conn_established, OVS_RO},
    {"offload-conn-established-api", "", 0, 0,
     test_offload_conn_established_api, OVS_RO},

    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_conntrack_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - 1,
        .argv = argv + 1,
    };
    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-conntrack", test_conntrack_main);

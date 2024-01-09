#!/usr/bin/env python3
#
# Copyright (c) 2022 Redhat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Script information:
# -------------------
# flow_reval_monitor.py uses the dpif_netlink_operate:flow_put and
# revalidator:flow_result USDT probes to monitor flow lifetimes and
# expiration events. By default, this will show all flow_put and flow
# expiration events, along with their reasons. This will look like so:
#
# TIME               UFID                                        EVENT/REASON
# 101536.226986736   ufid:f76fc899-376d-466b-bc74-0000b933eb97   flow_put
# 101536.227196214   ufid:d08472b6-110e-46cb-a9e4-00008f46838e   flow_put
# 101541.516610178   ufid:fc5cc4a2-39e7-4a2d-bbce-000019665b32   flow_put
# 101541.516967303   ufid:fddd6510-26dc-4c87-8f7a-0000fc0c2c3a   flow_put
# 101551.688050747   ufid:fddd6510-26dc-4c87-8f7a-0000fc0c2c3a   flow timed out
# 101551.688077175   ufid:fc5cc4a2-39e7-4a2d-bbce-000019665b32   flow timed out
# 101557.695391371   ufid:f76fc899-376d-466b-bc74-0000b933eb97   flow timed out
# 101557.695408909   ufid:d08472b6-110e-46cb-a9e4-00008f46838e   flow timed out
#
# flow key data can be printed using the --flow-keys option.  This will
# print the equivalent datapath flow string.
#
# When filtering flows, the syntax is the same as used by
# `ovs-appctl dpctl/add-flow`.
#
# The following options are available:
#
# usage: flow_reval_monitor.py [-h] [--buffer-page-count NUMBER]
#                              [-k [FLOW_KEYS]] [-p VSWITCHD_PID]
#                              [-D [DEBUG]] [-f [FLOW STRING ...]]
#
#  optional arguments:
#   -h, --help            show this help message and exit
#   --buffer-page-count NUMBER
#                         Number of BPF ring buffer pages, default 1024
#   -f <64..2048>, --flow-key-size=<64..2048>
#                         Set the size of the flow key, default 64
#   -k, --flow-keys       Print flow keys as flow strings
#   -l [FLOW_STRING ...], --filter-flows [FLOW_STRING ...]
#                         Filter flows that match the specified ODP-like flow
#   -p VSWITCHD_PID, --pid VSWITCHD_PID
#                         ovs-vswitchd's PID
#   -D [DEBUG], --debug [DEBUG]
#                         Enable eBPF debugging
#
# Examples:
#
# To use the script on a running ovs-vswitchd to see flow keys and expiration
# events for flows with an ipv4 source of 192.168.10.10:
# $ ./flow_reval_monitor.py --flow-keys --filter-flows \
#   "ipv4(src=192.168.10.10)"
# TIME               UFID                                          EVENT/REASON
# 105082.457322742   ufid:f76fc899-376d-466b-bc74-0000b933eb97     flow_put
# ufid:f76fc899-376d-466b-bc74-0000b933eb97 has the following flow information:
#     in_port(2),
#     eth(src=0e:04:47:fc:74:51, dst=da:dc:c5:69:05:d7), \
#     eth_type(0x800), \
#     ipv4(src=192.168.10.10, dst=192.168.10.30, proto=1, tos=0, ttl=64,[...]),
#     icmp(type=8, code=0)
# 105092.635450202   ufid:f76fc899-376d-466b-bc74-0000b933eb97   Flow timed out
#
# Notes:
#   1) No options are needed to attach when there is a single running instance
#      of ovs-vswitchd.
#   2) If you're using the flow filtering option, it will only track flows that
#      have been upcalled since the script began running.
#   3) When using the flow filtering option, the key size will likely need to
#      be expanded to match on all the fields in the message.  The default is
#      kept small to keep the buffer copy sizes down when displaying
#      flows (-k), but is hardcoded to 2048 when an actual filter (-l) is
#      applied

try:
    from bcc import BPF
    from bcc import USDT
    from bcc import USDTException
except ModuleNotFoundError:
    print("ERROR: Can't find the BPF Compiler Collection Tools.")
    print("Please install them before running this script.")
    exit(1)

import argparse
from ipaddress import IPv4Address, IPv6Address
import psutil
import struct
import sys
import time

#
# eBPF source code
#
bpf_src = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#define MAX_KEY      <MAX_KEY_VAL>
#define FLOW_FILTER  <FILTER_BOOL>

enum probe { OP_FLOW_PUT, FLOW_RESULT };

typedef union ovs_u128 {
    unsigned int ufid32[4];
    unsigned long long ufid64[2];
} ovs_u128;

struct dpif_flow_put {
    int flags;
    void *key_ptr;
    size_t key_len;
    void *mask_ptr;
    size_t mask_len;
    u64 action_ptr;
    size_t action_len;
    void *ufid_ptr;
};

struct udpif_key {
    void *cmap_node;
    void *key_ptr;
    size_t key_len;
    void *mask_ptr;
    size_t mask_len;
    ovs_u128 ufid;
};

struct event_t {
    u64 ts;
    u32 reason;
    u32 ufid[4]; /* Can't seem to make the ovs_u128 pass to python side. */
    u64 key_size;
    u8 key[MAX_KEY];
    enum probe probe;
};

BPF_HASH(watchlist, ovs_u128);
BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_COUNT>);

int usdt__flow_result(struct pt_regs *ctx) {
    u64 *ufid_present = NULL;
    struct udpif_key ukey;

    bpf_usdt_readarg_p(3, ctx, &ukey, sizeof ukey);
    ovs_u128 ufid = ukey.ufid;
    ufid_present = watchlist.lookup(&ufid);
    if(FLOW_FILTER && !ufid_present) {
        return 0;
    }

    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if(!event) {
        /* If we can't reserve the space in the ring buffer, return 1. */
        return 1;
    }

    event->probe = FLOW_RESULT;
    event->ts = bpf_ktime_get_ns();
    bpf_probe_read(&event->ufid, sizeof ufid, &ufid);
    bpf_usdt_readarg(1, ctx, &event->reason);
    events.ringbuf_submit(event, 0);

    return 0;
};


int usdt__op_flow_put(struct pt_regs *ctx) {
    struct dpif_flow_put put;
    ovs_u128 ufid;

    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if(!event) {
        /* If we can't reserve the space in the ring buffer, return 1. */
        return 1;
    }

    event->probe = OP_FLOW_PUT;
    event->ts = bpf_ktime_get_ns();
    bpf_usdt_readarg_p(2, ctx, &put, sizeof put);
    bpf_probe_read(&event->ufid, sizeof event->ufid, put.ufid_ptr);
    bpf_probe_read(&ufid, sizeof ufid, &event->ufid);
    if (put.key_len > MAX_KEY) {
        put.key_len = MAX_KEY;
    }
    event->key_size = put.key_len;
    bpf_probe_read(&event->key, put.key_len, put.key_ptr);
    event->reason = 0;
    events.ringbuf_submit(event, 0);

    watchlist.increment(ufid);
    return 0;
};
"""


#
# buffer_size_type()
#
def buffer_size_type(astr, min=64, max=2048):
    value = int(astr)
    if min <= value <= max:
        return value
    else:
        raise argparse.ArgumentTypeError(
            'value not in range {}-{}'.format(min, max))


#
# format_ufid()
#
def format_ufid(ufid):
    if ufid is None:
        return "ufid:none"

    return "ufid:{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:08x}".format(
           ufid[0], ufid[1] >> 16, ufid[1] & 0xffff,
           ufid[2] >> 16, ufid[2] & 0, ufid[3])


#
# find_and_delete_from_watchlist()
#
def find_and_delete_from_watchlist(event):
    for k, _ in b["watchlist"].items():
        key_ufid = struct.unpack("=IIII", k)
        if key_ufid == tuple(event.ufid):
            key = (b["watchlist"].Key * 1)(k)
            b["watchlist"].items_delete_batch(key)
            break


#
# handle_flow_put()
#
def handle_flow_put(event):
    if args.flow_keys or args.filter_flows is not None:
        key = decode_key(bytes(event.key)[:event.key_size])
        flow_dict, flow_str = parse_flow_dict(key)
        # For each attribute that we're watching.
        if args.filter_flows is not None:
            if not compare_flow_to_target(args.filter_flows, flow_dict):
                find_and_delete_from_watchlist(event)
                return

    print("{:<18.9f} {:<45} {:<13}".format(event.ts / 1000000000,
          format_ufid(event.ufid), "Insert (put) flow to kernel."))

    if args.flow_keys:
        if len(flow_str) > 80:
            flow_str = "    " + "),\n    ".join(flow_str.split("), "))
        else:
            flow_str = "    " + flow_str
        print(" - It holds the following flow information:")
        print(flow_str)


#
# compare_flow_to_target()
#
def compare_flow_to_target(target, flow):
    for key in target:
        if key not in flow:
            return False
        elif target[key] is True:
            continue
        elif target[key] == flow[key]:
            continue
        elif isinstance(target[key], dict) and isinstance(flow[key], dict):
            return compare_flow_to_target(target[key], flow[key])
        else:
            return False
    return True


#
# parse_flow_str()
#
def parse_flow_str(flow_str):
    f_list = [i.strip(", ") for i in flow_str.split(")")]
    if f_list[-1] == "":
        f_list = f_list[:-1]
    flow_dict = {}
    for e in f_list:
        split_list = e.split("(")
        k = split_list[0]
        if len(split_list) == 1:
            flow_dict[k] = True
        elif split_list[1].count("=") == 0:
            flow_dict[k] = split_list[1]
        else:
            sub_dict = {}
            sublist = [i.strip() for i in split_list[1].split(",")]
            for subkey in sublist:
                brk = subkey.find("=")
                sub_dict[subkey[:brk]] = subkey[brk + 1:]
            flow_dict[k] = sub_dict
    return flow_dict


#
# print_expiration()
#
def print_expiration(event):
    reasons = ["Unknown flow expiration reason!", "Flow timed out",
               "Flow revalidation too expensive",
               "Flow needs narrower wildcard mask",
               "Bad ODP flow fit", "Flow with associated ofproto",
               "Flow translation error", "Flow cache avoidance",
               "Kill them all signal"]

    ufid_str = format_ufid(event.ufid)
    reason = event.reason

    if reason not in range(0, len(reasons) - 1):
        reason = 0
    print("{:<18.9f} {:<45} {:<17}".
          format(event.ts / 1000000000, ufid_str, reasons[reason]))


#
# decode_key()
#
def decode_key(msg):
    bytes_left = len(msg)
    result = {}
    while bytes_left:
        if bytes_left < 4:
            break
        nla_len, nla_type = struct.unpack("=HH", msg[:4])
        if nla_len < 4:
            break
        nla_data = msg[4:nla_len]
        trunc = False
        if nla_len > bytes_left:
            trunc = True
            nla_data = nla_data[:(bytes_left - 4)]
        else:
            result[get_ovs_key_attr_str(nla_type)] = nla_data
        if trunc:
            break
        next_offset = (nla_len + 3) & (~3)
        msg = msg[next_offset:]
        bytes_left -= next_offset
    return result


#
# get_ovs_key_attr_str()
#
def get_ovs_key_attr_str(attr):
    ovs_key_attr = ["OVS_KEY_ATTR_UNSPEC",
                    "encap",
                    "skb_priority",
                    "in_port",
                    "eth",
                    "vlan",
                    "eth_type",
                    "ipv4",
                    "ipv6",
                    "tcp",
                    "udp",
                    "icmp",
                    "icmpv6",
                    "arp",
                    "nd",
                    "skb_mark",
                    "tunnel",
                    "sctp",
                    "tcp_flags",
                    "dp_hash",
                    "recirc_id",
                    "mpls",
                    "ct_state",
                    "ct_zone",
                    "ct_mark",
                    "ct_label",
                    "ct_tuple4",
                    "ct_tuple6",
                    "nsh"]

    if attr < 0 or attr > len(ovs_key_attr):
        return "<UNKNOWN>: {}".format(attr)
    return ovs_key_attr[attr]


#
# is_nonzero()
#
def is_nonzero(val):
    if isinstance(val, int):
        return (val != 0)

    if isinstance(val, str):
        val = bytes(val, "utf-8")

    # If it's not a string or an int, it's bytes.
    return (val.count(0) < len(val))


#
# parse_flow_dict()
#
def parse_flow_dict(key_dict, decode=True):
    ret_str = ""
    parseable = {}
    skip = ["nsh", "tunnel", "mpls", "vlan"]
    need_byte_swap = ["ct_label"]
    ipv4addrs = ["ct_tuple4", "tunnel", "ipv4", "arp"]
    ipv6addrs = ["ipv6", "nd", "ct_tuple6"]
    macs = {"eth": [0, 1], "arp": [3, 4], "nd": [1, 2]}
    fields = [("OVS_KEY_ATTR_UNSPEC"),
              ("encap", ),
              ("skb_priority", "<I"),
              ("in_port", "<I"),
              ("eth", "!6s6s", "src", "dst"),
              ("vlan", ),
              ("eth_type", "!H"),
              ("ipv4", "!4s4s4B", "src", "dst", "proto", "tos", "ttl", "frag"),
              ("ipv6", "!16s16s4s4B", "src", "dst",
               "label", "proto", "tclass", "hlimit", "frag"),
              ("tcp", "!2H", "src", "dst"),
              ("udp", "!2H", "src", "dst"),
              ("icmp", "!2B", "type", "code"),
              ("icmpv6", "!2B", "type", "code"),
              ("arp", "!4s4sH6s6s", "sip", "tip", "op", "sha", "tha"),
              ("nd", "!16s6s6s", "target", "sll", "tll"),
              ("skb_mark", "<I"),
              ("tunnel", ),
              ("sctp", "!2H", "src", "dst"),
              ("tcp_flags", "!H"),
              ("dp_hash", "<I"),
              ("recirc_id", "<I"),
              ("mpls", ),
              ("ct_state", "<I"),
              ("ct_zone", "<H"),
              ("ct_mark", "<I"),
              ("ct_label", "!16s"),
              ("ct_tuple4",
               "!4s4s2HB", "src", "dst", "tp_src", "tp_dst", "proto"),
              ("ct_tuple6",
               "!16s16sB2H", "src", "dst", "proto", "tp_src", "tp_dst"),
              ("nsh", )]
    for k, v in key_dict.items():
        s = ""
        if k in skip:
            continue
        if decode and int.from_bytes(v, "big") == 0:
            parseable[k] = "0"
            continue
        if decode and k in need_byte_swap:
            v = int.from_bytes(v, "little").to_bytes(len(v), "big")
        attr = -1
        found = False
        for f in fields:
            if k == f[0]:
                attr = fields.index(f)
                found = True
                break
        if not found:
            raise KeyError("Invalid flow field '%s'" % k)
        if decode and len(fields[attr]) > 1:
            data = list(struct.unpack(fields[attr][1],
                        v[:struct.calcsize(fields[attr][1])]))
            if k in ipv4addrs:
                if data[0].count(0) < 4:
                    data[0] = str(IPv4Address(data[0]))
                else:
                    data[0] = b"\x00"
                if data[1].count(0) < 4:
                    data[1] = str(IPv4Address(data[1]))
                else:
                    data[1] = b"\x00"
            if k in ipv6addrs:
                if data[0].count(0) < 16:
                    data[0] = str(IPv6Address(data[0]))
                else:
                    data[0] = b"\x00"
                if data[1].count(0) < len(data[1]):
                    data[1] = str(IPv6Address(data[1]))
                else:
                    data[1] = b"\x00"
            if k in macs.keys():
                for e in macs[k]:
                    if data[e].count(0) == 6:
                        mac_str = b"\x00"
                    else:
                        mac_str = ":".join(["%02x" % i for i in data[e]])
                    data[e] = mac_str
        if decode and len(fields[attr]) > 2:
            field_dict = {field: d for field, d in zip(fields[attr][2:], data)}
            s = ", ".join(k + "=" + str(v) for k, v in field_dict.items())
        elif decode and k != "eth_type":
            s = str(data[0])
            field_dict = s
        else:
            if decode:
                s = hex(data[0])
            field_dict = s
        ret_str += k + "(" + s + "), "
        parseable[k] = field_dict
    ret_str = ret_str[:-2]
    return (parseable, ret_str)


#
# handle_event()
#
def handle_event(ctx, data, size):
    # Once we grab the event, we have three cases.
    # 1. It's a revalidator probe and the reason is nonzero: A flow is expiring
    # 2. It's a revalidator probe and the reason is zero: flow revalidated
    # 3. It's a flow_put probe.
    #
    # We will ignore case 2, and report all others.
    #
    event = b["events"].event(data)
    if event.probe == 0:  # OP_FLOW_PUT
        handle_flow_put(event)
    elif event.probe == 1 and event.reason > 0:  # FLOW_RESULT
        print_expiration(event)


def main():
    #
    # Don't like these globals, but ctx passing does not work with the existing
    # open_ring_buffer() API :(
    #
    global b
    global args

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()
    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-f", "--flow-key-size",
                        help="Set maximum flow key size to capture, "
                        "default 64 - see notes", type=buffer_size_type,
                        default=64, metavar="[64-2048]")
    parser.add_argument("-k", "--flow-keys",
                        help="Print flow keys as flow strings",
                        action="store_true")
    parser.add_argument("-l", "--filter-flows", metavar="FLOW_STRING",
                        help="Filter flows that match the specified "
                        "ODP-like flow",
                        type=str, default=None, nargs="*")
    parser.add_argument("-p", "--pid", metavar="VSWITCHD_PID",
                        help="ovs-vswitchd's PID", type=int, default=None)
    parser.add_argument("-D", "--debug", help="Enable eBPF debugging",
                        type=int, const=0x3f, default=0, nargs="?")
    args = parser.parse_args()

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if args.pid is None:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if args.pid is not None:
                    print("Error: Multiple ovs-vswitchd daemons running, "
                          "use the -p option!")
                    sys.exit(-1)

                args.pid = proc.pid
    #
    # Error checking on input parameters
    #
    if args.pid is None:
        print("ERROR: Failed to find ovs-vswitchd's PID!")
        sys.exit(-1)

    #
    # Attach the USDT probes
    #
    u = USDT(pid=int(args.pid))
    try:
        u.enable_probe(probe="op_flow_put", fn_name="usdt__op_flow_put")
    except USDTException as e:
        print("Error attaching the dpif_netlink_operate__:op_flow_put probe.")
        print(str(e))
        sys.exit(-1)

    try:
        u.enable_probe(probe="flow_result", fn_name="usdt__flow_result")
    except USDTException as e:
        print("Error attaching the revalidate:flow_result probe.")
        print(str(e))
        sys.exit(-1)

    #
    # Attach the probes to the running process
    #
    source = bpf_src.replace("<BUFFER_PAGE_COUNT>",
                             str(args.buffer_page_count))

    if args.filter_flows is None:
        filter_bool = 0

        # Set the key size based on what the user wanted
        source = source.replace("<MAX_KEY_VAL>", str(args.flow_key_size))
    else:
        filter_bool = 1
        args.filter_flows = parse_flow_str(args.filter_flows[0])

        # Run through the parser to make sure we only filter on fields we
        # understand
        parse_flow_dict(args.filter_flows, False)

        # This is hardcoded here because it doesn't make sense to shrink the
        # size, since the flow key might be missing fields that are matched in
        # the flow filter.
        source = source.replace("<MAX_KEY_VAL>", "2048")

    source = source.replace("<FILTER_BOOL>", str(filter_bool))

    b = BPF(text=source, usdt_contexts=[u], debug=args.debug)

    #
    # Print header
    #
    print("{:<18} {:<45} {:<17}".format("TIME", "UFID", "EVENT/REASON"))

    #
    # Dump out all events.
    #
    b["events"].open_ring_buffer(handle_event)
    while 1:
        try:
            b.ring_buffer_poll()
            time.sleep(0.5)
        except KeyboardInterrupt:
            break


#
# Start main() as the default entry point
#
if __name__ == "__main__":
    main()

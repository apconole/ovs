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

#include "conntrack-private.h"
#include "dp-packet.h"
#include "ovs-thread.h"
#include "packets.h"

static void
handle_tftp_ctl(struct conntrack *ct,
                const struct conn_lookup_ctx *ctx OVS_UNUSED,
                struct dp_packet *pkt, struct conn *conn_for_expectation,
                long long now OVS_UNUSED, enum ftp_ctl_pkt ftp_ctl OVS_UNUSED,
                bool nat OVS_UNUSED)
{
    expectation_create(ct,
                       conn_for_expectation->key_node[CT_DIR_FWD].key.src.port,
                       conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
}

void
conntrack_tftp_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        alg_helpers[CT_ALG_CTL_TFTP] = handle_tftp_ctl;
        ovsthread_once_done(&once);
    }
}

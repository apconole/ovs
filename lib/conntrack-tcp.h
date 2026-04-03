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

#ifndef CONNTRACK_TCP_H
#define CONNTRACK_TCP_H

#include "conntrack.h"
#include "ct-dpif.h"

/* wscale field flags stored in tcp_peer.wscale. */
#define CT_WSCALE_FLAG    0x80  /* Negotiated window scaling is in use. */
#define CT_WSCALE_UNKNOWN 0x40  /* Scale factor not yet known. */
#define CT_WSCALE_MASK    0x0f  /* Actual scale factor (0-14). */

/* Per-direction TCP state tracked by the conntrack TCP module. */
struct tcp_peer {
    uint32_t               seqlo;    /* Max sequence number sent. */
    uint32_t               seqhi;    /* Max the other end ACKd + win. */
    uint16_t               max_win;  /* Largest window (pre-scaling). */
    uint8_t                wscale;   /* Window scaling factor + flags. */
    enum ct_dpif_tcp_state state;
};

/* TCP-specific connection state stored in the conntrack private data slot.
 * Access via conn_tcp_state_get(). */
struct conn_tcp_state {
    struct tcp_peer peer[2]; /* peer[0]=original, peer[1]=reply. */
};

/* Private slot ID for TCP state; valid after conntrack_tcp_init(). */
extern ct_private_id_t conntrack_tcp_private_id;

/* Must be called once at module initialization before any connections are
 * created (called internally by conntrack_init()). */
void conntrack_tcp_init(void);

/* Returns the TCP state for 'conn', or NULL if not a TCP connection or
 * conntrack_tcp_init() has not been called. */
static inline struct conn_tcp_state *
conn_tcp_state_get(const struct conn *conn)
{
    if (conntrack_tcp_private_id == CT_PRIVATE_ID_INVALID) {
        return NULL;
    }
    return conn_private_get(conn, conntrack_tcp_private_id);
}

#endif /* CONNTRACK_TCP_H */

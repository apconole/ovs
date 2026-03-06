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

#ifndef CT_STATE_H
#define CT_STATE_H 1

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

#endif /* ct-state.h */

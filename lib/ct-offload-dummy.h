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

#ifndef CT_OFFLOAD_DUMMY_H
#define CT_OFFLOAD_DUMMY_H 1

/* Dummy CT offload provider
 * =========================
 *
 * A software-only implementation of the ct_offload_class interface used for
 * unit testing.  It records every conn_add/conn_del/conn_update call and
 * exposes inspection helpers so tests can verify that the correct hooks are
 * reached without requiring any hardware.
 *
 * Typical usage:
 *
 *   ct_offload_dummy_register();   // activate the provider
 *   conntrack_execute(...);        // exercises conn_add
 *   ovs_assert(ct_offload_dummy_n_added() == 1);
 *   conntrack_flush(...);          // exercises conn_del
 *   ovs_assert(ct_offload_dummy_n_deleted() == 1);
 *   ct_offload_dummy_unregister(); // tear down after test
 */

#include <stdbool.h>

struct conn;

/* Register (or unregister) the dummy provider.
 *
 * ct_offload_dummy_register() also marks CT offload as "enabled" within the
 * dummy so that the guards in conntrack.c fire even without hardware offload
 * being configured globally.  Call ct_offload_dummy_unregister() to undo. */
void ct_offload_dummy_register(void);
void ct_offload_dummy_unregister(void);

/* Counters — reset to zero by ct_offload_dummy_register(). */
unsigned int ct_offload_dummy_n_added(void);
unsigned int ct_offload_dummy_n_deleted(void);
unsigned int ct_offload_dummy_n_updated(void);

/* Reset all counters without changing registered state. */
void ct_offload_dummy_reset_counters(void);

/* Returns true if 'conn' is currently tracked by the dummy (was added but
 * not yet deleted or flushed). */
bool ct_offload_dummy_contains(const struct conn *conn);

#endif /* CT_OFFLOAD_DUMMY_H */

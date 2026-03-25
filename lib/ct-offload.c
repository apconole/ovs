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

#include <config.h>
#include <errno.h>

#include "ct-offload.h"
#include "ovs-thread.h"
#include "util.h"

#include "openvswitch/list.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_offload);

/* Node in the registered-provider list. */
struct ct_offload_class_node {
    const struct ct_offload_class *class;
    struct ovs_list               list_node;
};

/* Global list of registered CT offload classes and a mutex to protect it.
 * Providers are expected to be registered at module init time and
 * unregistered only at module teardown, so contention is minimal. */
static struct ovs_mutex ct_offload_mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_list  ct_offload_classes
    OVS_GUARDED_BY(ct_offload_mutex)
    = OVS_LIST_INITIALIZER(&ct_offload_classes);


/* ct_offload_register() - register a CT offload provider class.
 *
 * Calls class->init() if provided.  Returns 0 on success or a positive
 * errno value on failure.  Attempting to register the same class twice
 * returns EEXIST. */
int
ct_offload_register(const struct ct_offload_class *class)
{
    struct ct_offload_class_node *node;
    int error = 0;

    ovs_assert(class);
    ovs_assert(class->name);

    ovs_mutex_lock(&ct_offload_mutex);

    /* Detect duplicate registrations. */
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (!strcmp(node->class->name, class->name)) {
            VLOG_WARN("attempted to register duplicate ct offload class: %s",
                      class->name);
            error = EEXIST;
            goto out;
        }
    }

    error = class->init ? class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize ct offload class %s: %s",
                  class->name, ovs_strerror(error));
        goto out;
    }

    node = xmalloc(sizeof *node);
    node->class = class;
    ovs_list_push_back(&ct_offload_classes, &node->list_node);
    VLOG_DBG("registered ct offload class: %s", class->name);

out:
    ovs_mutex_unlock(&ct_offload_mutex);
    return error;
}

/* ct_offload_unregister() - unregister a previously registered class.
 *
 * Safe to call even if the class was never registered (no-op in that
 * case). */
void
ct_offload_unregister(const struct ct_offload_class *class)
{
    struct ct_offload_class_node *node;

    ovs_assert(class);

    ovs_mutex_lock(&ct_offload_mutex);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (node->class == class) {
            ovs_list_remove(&node->list_node);
            free(node);
            VLOG_DBG("unregistered ct offload class: %s", class->name);
            goto out;
        }
    }
    VLOG_WARN("attempted to unregister unknown ct offload class: %s",
              class->name);

out:
    ovs_mutex_unlock(&ct_offload_mutex);
}

/* ct_offload_module_init() - register built-in CT offload providers.
 *
 * Must be called once before any connections are created. */
void
ct_offload_module_init(void)
{
    /* No built-in providers yet; third parties call ct_offload_register()
     * directly from their own module-init routines. */
}

/* ct_offload_conn_add() - notify all eligible providers of a new connection.
 *
 * Iterates over registered providers and calls conn_add() on each one that
 * reports can_offload() == true for this context.  Returns the first non-zero
 * error encountered, but continues notifying remaining providers.  This allows
 * the underlying hardware conntrack details across providers function. */
int
ct_offload_conn_add(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;
    int ret = 0;

    ovs_mutex_lock(&ct_offload_mutex);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->can_offload && !class->can_offload(ctx)) {
            continue;
        }
        if (class->conn_add) {
            int error = class->conn_add(ctx);

            if (error && !ret) {
                ret = error;
            }
        }
    }
    ovs_mutex_unlock(&ct_offload_mutex);

    return ret;
}

/* ct_offload_conn_del() - notify all providers that a connection was removed.
 *
 * Called unconditionally on all providers so that each can clean up any
 * state it may have installed. */
void
ct_offload_conn_del(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;

    ovs_mutex_lock(&ct_offload_mutex);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->conn_del) {
            class->conn_del(ctx);
        }
    }
    ovs_mutex_unlock(&ct_offload_mutex);
}

/* ct_offload_conn_update() - query the hardware last-used timestamp.
 *
 * Iterates over providers and returns the first non-zero timestamp returned
 * by a provider's conn_update() callback.  Returns 0 if no provider
 * supplies a timestamp. */
long long
ct_offload_conn_update(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;
    long long last_used = 0;

    ovs_mutex_lock(&ct_offload_mutex);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->conn_update) {
            long long ts = class->conn_update(ctx);

            if (ts) {
                last_used = ts;
                break;
            }
        }
    }
    ovs_mutex_unlock(&ct_offload_mutex);

    return last_used;
}

/* ct_offload_can_offload() - returns true if any provider can offload ctx. */
bool
ct_offload_can_offload(const struct ct_offload_ctx *ctx)
{
    struct ct_offload_class_node *node;
    bool result = false;

    ovs_mutex_lock(&ct_offload_mutex);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->can_offload && class->can_offload(ctx)) {
            result = true;
            break;
        }
    }
    ovs_mutex_unlock(&ct_offload_mutex);

    return result;
}

/* ct_offload_flush() - flush all offloaded connections from every provider. */
void
ct_offload_flush(void)
{
    struct ct_offload_class_node *node;

    ovs_mutex_lock(&ct_offload_mutex);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        const struct ct_offload_class *class = node->class;

        if (class->flush) {
            class->flush();
        }
    }
    ovs_mutex_unlock(&ct_offload_mutex);
}

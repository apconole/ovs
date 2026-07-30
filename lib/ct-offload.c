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

#include "ct-offload.h"

#include <errno.h>

#include "ovs-thread.h"
#include "util.h"

#include "openvswitch/list.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_offload);

/* Node in the registered-provider list. */
struct ct_offload_class_node {
    const struct ct_offload_class *class;
    int refcnt;                     /* Number of open users; providers with
                                     * a zero refcnt are registered but not
                                     * active and do not see operations.
                                     * Written under the write lock, read
                                     * under the read lock. */
    struct ovs_list list_node;
};

/* Global list of registered CT offload classes and a rwlock to protect it.
 * Write lock is held only during register/unregister/open/close; fast-path
 * operations hold the read lock so multiple PMD threads can iterate
 * concurrently. */
static struct ovs_rwlock ct_offload_rwlock = OVS_RWLOCK_INITIALIZER;
static struct ovs_list ct_offload_classes
    OVS_GUARDED_BY(ct_offload_rwlock)
    = OVS_LIST_INITIALIZER(&ct_offload_classes);

/* Looks up 'name' in the registered class list.  The caller must hold
 * ct_offload_rwlock. */
static struct ct_offload_class_node *
ct_offload_class_find__(const char *name)
    OVS_REQUIRES(ct_offload_rwlock)
{
    struct ct_offload_class_node *node;

    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (!strcmp(node->class->name, name)) {
            return node;
        }
    }
    return NULL;
}

/* ct_offload_register() - register a CT offload provider class.
 *
 * Calls class->init() if provided.  Registration does not activate the
 * provider; the dpif-offload provider must call ct_offload_open() for
 * that.  Returns 0 on success or a positive errno value on failure.
 * Attempting to register the same class name twice returns EEXIST. */
int
ct_offload_register(const struct ct_offload_class *class)
{
    struct ct_offload_class_node *node;
    int error = 0;

    ovs_assert(class);
    ovs_assert(class->name);
    ovs_assert(class->flow_might_offload);

    ovs_rwlock_wrlock(&ct_offload_rwlock);

    if (ct_offload_class_find__(class->name)) {
        VLOG_WARN("attempted to register duplicate ct offload class: %s",
                  class->name);
        error = EEXIST;
        goto out;
    }

    error = class->init ? class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize ct offload class %s: %s",
                  class->name, ovs_strerror(error));
        goto out;
    }

    node = xmalloc(sizeof *node);
    node->class = class;
    node->refcnt = 0;
    ovs_list_push_back(&ct_offload_classes, &node->list_node);
    VLOG_DBG("registered ct offload class: %s", class->name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
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

    ovs_rwlock_wrlock(&ct_offload_rwlock);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (node->class == class) {
            if (node->refcnt > 0) {
                VLOG_WARN("unregistering still-open ct offload class: %s",
                          class->name);
            }
            ovs_list_remove(&node->list_node);
            free(node);
            VLOG_DBG("unregistered ct offload class: %s", class->name);
            goto out;
        }
    }
    VLOG_WARN("attempted to unregister unknown ct offload class: %s",
              class->name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
}

/* ct_offload_open() - activate the named provider for use.
 *
 * Called by the dpif-offload provider that owns the ports and hardware
 * resources when it needs conntrack offload from the named provider.
 * Opens are refcounted; class->open() runs on the first open.  Returns 0
 * on success or a positive errno value on failure. */
int
ct_offload_open(const char *name)
{
    struct ct_offload_class_node *node;
    int error = 0;

    ovs_rwlock_wrlock(&ct_offload_rwlock);
    node = ct_offload_class_find__(name);
    if (!node) {
        VLOG_INFO("attempted to open unknown ct offload class: %s", name);
        error = ENOENT;
        goto out;
    }

    if (node->refcnt == 0 && node->class->open) {
        error = node->class->open();
        if (error) {
            VLOG_WARN("failed to open ct offload class %s: %s",
                      name, ovs_strerror(error));
            goto out;
        }
    }
    node->refcnt++;
    VLOG_DBG("opened ct offload class: %s", name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
    return error;
}

/* ct_offload_close() - release a previously opened provider.
 *
 * Paired with an earlier successful ct_offload_open().  class->close()
 * runs when the last opener releases the provider. */
void
ct_offload_close(const char *name)
{
    struct ct_offload_class_node *node;

    ovs_rwlock_wrlock(&ct_offload_rwlock);
    node = ct_offload_class_find__(name);
    if (!node || node->refcnt == 0) {
        VLOG_WARN("attempted to close non-open ct offload class: %s", name);
        goto out;
    }

    if (--node->refcnt == 0 && node->class->close) {
        node->class->close();
    }
    VLOG_DBG("closed ct offload class: %s", name);

out:
    ovs_rwlock_unlock(&ct_offload_rwlock);
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

/* ct_offload_flow_offloadable() - may a flow containing the ct()
 * action 'ct_action' with flow key 'match' on 'netdev_in' be fully
 * offloaded?  Returns true if any open provider claims it. */
bool
ct_offload_flow_offloadable(struct netdev *netdev_in,
                            const struct match *match,
                            const struct nlattr *ct_action)
{
    struct ct_offload_flow_ctx ctx = {
        .netdev_in = netdev_in,
        .match = match,
        .ct_action = ct_action,
    };
    struct ct_offload_class_node *node;
    bool result = false;

    ovs_rwlock_rdlock(&ct_offload_rwlock);
    LIST_FOR_EACH (node, list_node, &ct_offload_classes) {
        if (node->refcnt == 0) {
            continue;
        }
        if (node->class->flow_might_offload(&ctx)) {
            result = true;
            break;
        }
    }
    ovs_rwlock_unlock(&ct_offload_rwlock);

    return result;
}

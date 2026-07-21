..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

==========================================
Userspace Datapath - Conntrack Offloading
==========================================

This document describes the conntrack offloading infrastructure in the OVS
userspace datapath, explains the design rationale, and provides a step-by-step
guide for hardware vendors implementing a conntrack offload provider.

Overview
--------

Open vSwitch contains a userspace connection tracking (conntrack) engine
derived from the OpenBSD pf stack.  For every packet that carries a
``ct()`` action, OVS runs the packet through ``conntrack_execute()`` and
``process_one()``, which update connection state in software.

Modern hardware — SmartNICs, DPUs, and accelerator ASICs — often include a
native CT engine that can track connection state and report last-used
timestamps without involving the host CPU.  The conntrack offload framework
(``ct_offload_class``) provides the lifecycle event hooks that such hardware
needs to stay in sync with the OVS software CT table.

Architecture
------------

Conntrack offloading is deliberately kept separate from flow offloading
(``dpif_offload_class``).  The two layers serve different purposes:

* **Flow offloading** (``dpif_offload_class``): installs match/action rules
  in hardware — the equivalent of an ``rte_flow`` or TC flower rule.  After
  an upcall installs a datapath flow, the dpif-offload layer can push that
  rule to hardware so subsequent packets matching the same 5-tuple never
  cause a further upcall.

* **Conntrack offloading** (``ct_offload_class``): notifies hardware of
  connection lifecycle events — new connections, bidirectional establishment,
  idle-timeout queries, and deletion.  Hardware uses these events to maintain
  its own CT state tables, which may be separate from the hardware flow table.

A real hardware provider will typically implement **both** interfaces: the
dpif-offload side to push forwarding rules, and the ct-offload side to program
hardware CT state.  The two interfaces share a common anchor: the
``struct netdev *`` passed in ``ct_offload_ctx.netdev_in`` identifies the
hardware port, and a provider can recover its ``dpif_offload`` instance from
``netdev->dpif_offload`` (as done in the DPDK and TC providers).

Software conntrack always runs for the first packets of a new connection.
Once the hardware has been programmed (via ``conn_add`` / ``conn_established``),
the provider's dpif-offload side installs a hardware flow rule that matches
all subsequent packets for the connection before OVS's software path, removing
them from the upcall / conntrack loop entirely.  The ct-offload callbacks then
serve two ongoing roles: ``conn_update`` extends the software expiry timer when
hardware confirms the connection is still active, and ``conn_del`` cleans up
hardware state when OVS decides to retire the connection.

Connection Lifecycle
--------------------

The following state machine shows when each callback fires and what the
provider is expected to do at each transition::

    packet arrives, ct(commit)
           |
           v
      [ conn_add ]  ──── hardware: allocate CT entry, store conn* → handle map
           |
           |  ... forward packets flow through hardware ...
           |
           v
    reply packet seen, CS_ESTABLISHED | CS_REPLY_DIR
           |
           v
    [ conn_established ] ── hardware: update CT entry with reply-direction port;
           |                           return true to mark connection fully in HW
           |
           |  ... bidirectional traffic flows through hardware ...
           |
           |  OVS expiry timer fires
           |
           v
     [ conn_update ] ─── hardware: return last-used timestamp (ms since epoch)
           |                        or 0 if connection unknown / expired in HW
           |
           |  if timestamp > current expiry: connection stays alive
           |
           v
    OVS decides to expire (or dpctl/flush-conntrack called)
           |
           v
      [ conn_del ]  ──── hardware: look up conn* → handle map, remove CT entry


``conn_established`` is called **exactly once** per connection: the first time
a reply-direction packet is seen while the connection is in the
``CT_OFFLOAD_STATE_ADDED`` state.  If ``conn_established`` returns ``true``,
OVS transitions the connection to ``CT_OFFLOAD_STATE_EST``.  If it returns
``false`` (the provider did not confirm hardware establishment), the state
remains ``CT_OFFLOAD_STATE_ADDED`` and ``conn_established`` will be called
again on the next eligible reply packet.

``conn_update`` is called periodically on offloaded connections while OVS's
idle timer is running.  A non-zero return value refreshes the software expiry,
keeping the connection alive as long as hardware reports activity.

The ``ct_offload_ctx`` Structure
---------------------------------

Every callback receives a ``const struct ct_offload_ctx *`` with the following
fields:

``conn``
    Pointer to the OVS connection object.  Stable for the lifetime of the
    connection (from ``conn_add`` through ``conn_del``).  Use this as the key
    in any internal ``conn* → hardware_handle`` map.

``netdev_in``
    The input ``struct netdev *`` for the packet that triggered this event.
    Non-NULL at ``conn_add`` (forward-direction input port) and at
    ``conn_established`` (reply-direction input port).  **NULL at ``conn_del``
    and ``conn_update``** — the provider must look up its hardware state by
    ``conn`` instead.

``input_port_id``
    ODP port number corresponding to ``netdev_in``.  Provided for convenience;
    the same information can be derived from ``netdev_in``.

The ``ct_offload_class`` Interface
------------------------------------

Mandatory callbacks
~~~~~~~~~~~~~~~~~~~

``can_offload(ctx)``
    Called before ``conn_add`` to determine whether this provider will handle
    the connection.  Return ``true`` to accept the connection; return ``false``
    to decline (the connection will not be added to this provider).  A minimal
    implementation can simply return ``true`` for all connections.

``conn_add(ctx)``
    Called when a new connection is committed (``ct(commit)``).
    ``ctx->netdev_in`` identifies the forward-direction input port; use it to
    find the hardware device (e.g. ``ctx->netdev_in->dpif_offload``).  Allocate
    a hardware CT entry and store a ``conn* → hardware_handle`` mapping
    internally.  Return 0 on success or a positive ``errno`` on failure.

``conn_del(ctx)``
    Called when OVS removes a connection (expiry or flush).  ``ctx->netdev_in``
    is NULL; look up the hardware handle by ``ctx->conn``.  Remove the hardware
    CT entry and free internal state.

Optional callbacks
~~~~~~~~~~~~~~~~~~

``conn_established(ctx)``
    Called exactly once when the first reply-direction packet is seen for an
    offloaded connection, while OVS holds ``conn->lock``.  ``ctx->netdev_in``
    is the reply-direction input port.  Update the hardware CT entry with the
    reply port so the hardware knows both directions.  Return ``true`` if the
    connection is now fully established in hardware; return ``false`` if
    hardware establishment failed or was deferred.

    If this callback is NULL, the framework skips the established transition
    and the provider never receives bidirectional port information.

``conn_update(ctx)``
    Called periodically by the conntrack idle timer to query hardware for a
    last-used timestamp.  ``ctx->netdev_in`` is NULL; look up by ``ctx->conn``.
    Return the last-used time in milliseconds since epoch, or 0 if the
    connection is not found or no timestamp is available.  A non-zero return
    value causes OVS to refresh the connection's expiry timer, keeping
    long-running hardware-accelerated connections alive.

    If this callback is NULL, OVS relies solely on its own software idle timer,
    which will expire connections even if hardware is actively forwarding them.
    Implementing ``conn_update`` is strongly recommended for any provider that
    accelerates established connections.

``batch_submit(batch)``
    Alternative to per-connection callbacks for providers that benefit from
    bulk programming (e.g. single DMA ring submission).  If non-NULL,
    ``batch_submit`` is called with the full batch before the framework falls
    back to individual callbacks for any remaining operations.  Providers that
    do not need batching should leave this NULL.

``init()``
    One-time provider initialization called during ``ct_offload_register()``.
    Return 0 on success or a positive ``errno`` to abort registration.  May be
    NULL if no initialization is required.

``flush()``
    Remove all offloaded connections from hardware.  Called when OVS flushes
    the entire conntrack table (e.g. ``dpctl/flush-conntrack``).  May be NULL.

Registration and Automatic Activation
--------------------------------------

CT offload providers are registered with ``ct_offload_register()`` and
identified by a ``name`` string.  The framework automatically activates a
built-in provider if a dpif offload class with a matching ``type`` field is
already registered.

The activation path is::

    ovs-vsctl set Open_vSwitch . other_config:hw-offload=true
        |
        v
    dpif_offload_set_global_cfg()
        |
        +-- dpif_offload_module_init()   [first call only]
        |     registers all base dpif_offload_class entries
        |     (including "dummy", "tc", "dpdk") in the class shash
        |
        +-- sets offload_global_enabled = true
        |
        +-- ct_offload_set_global_cfg()  [first call only]
              calls ct_offload_module_init()
                for each built-in ct_offload_class:
                  if dpif_offload_class_is_registered(class->name):
                      ct_offload_register(class)

The key invariant is: **a ct_offload_class is activated if and only if a
dpif_offload_class with the same type string is already registered**.  For a
new hardware provider, this means:

* Set ``dpif_offload_class.type = "myhw"``
* Set ``ct_offload_class.name = "myhw"``
* Add both to their respective ``base_*_classes[]`` arrays in
  ``lib/dpif-offload.c`` and ``lib/ct-offload.c``.

When ``hw-offload`` is enabled, the CT offload module will check
``dpif_offload_class_is_registered("myhw")``; if true, it calls
``ct_offload_register(&ct_offload_myhw_class)`` automatically.

Implementing a New Provider
----------------------------

This section walks through a minimum viable implementation.

Step 1: Define a hardware handle type and internal state
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The provider owns the ``conn* → hardware_handle`` mapping.  A simple approach
uses a hash map or linked list protected by a mutex::

    struct myhw_ct_entry {
        struct hmap_node  hmap_node;  /* keyed by (uintptr_t)conn */
        const struct conn *conn;
        uint64_t          hw_handle;  /* opaque HW reference */
        struct netdev     *fwd_netdev;
        struct netdev     *rev_netdev;
    };

    static struct hmap    myhw_ct_table = HMAP_INITIALIZER(&myhw_ct_table);
    static struct ovs_mutex myhw_mutex  = OVS_MUTEX_INITIALIZER;

Step 2: Implement conn_add
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    static int
    myhw_conn_add(const struct ct_offload_ctx *ctx)
    {
        /* Recover the dpif_offload instance from the netdev. */
        struct dpif_offload *offload = ctx->netdev_in->dpif_offload;
        if (!offload) {
            return ENODEV;
        }

        uint64_t hw_handle;
        int err = myhw_program_ct_entry(offload, ctx->conn, &hw_handle);
        if (err) {
            return err;
        }

        struct myhw_ct_entry *e = xmalloc(sizeof *e);
        e->conn       = ctx->conn;
        e->hw_handle  = hw_handle;
        e->fwd_netdev = ctx->netdev_in;
        e->rev_netdev = NULL;

        ovs_mutex_lock(&myhw_mutex);
        hmap_insert(&myhw_ct_table, &e->hmap_node, (uintptr_t) ctx->conn);
        ovs_mutex_unlock(&myhw_mutex);
        return 0;
    }

Step 3: Implement conn_established
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    static bool
    myhw_conn_established(const struct ct_offload_ctx *ctx)
    {
        ovs_mutex_lock(&myhw_mutex);
        struct myhw_ct_entry *e = myhw_find__(ctx->conn);
        bool ok = false;

        if (e && !e->rev_netdev) {
            struct dpif_offload *offload = ctx->netdev_in->dpif_offload;
            if (offload && !myhw_update_ct_entry_rev(offload, e->hw_handle,
                                                     ctx->netdev_in)) {
                e->rev_netdev = ctx->netdev_in;
                ok = true;
            }
        }
        ovs_mutex_unlock(&myhw_mutex);
        return ok;
    }

Step 4: Implement conn_update
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    static long long
    myhw_conn_update(const struct ct_offload_ctx *ctx)
    {
        ovs_mutex_lock(&myhw_mutex);
        struct myhw_ct_entry *e = myhw_find__(ctx->conn);
        long long last_used = 0;

        if (e) {
            last_used = myhw_query_last_used(e->hw_handle);
        }
        ovs_mutex_unlock(&myhw_mutex);
        return last_used;  /* ms since epoch, or 0 */
    }

Step 5: Implement conn_del
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    static void
    myhw_conn_del(const struct ct_offload_ctx *ctx)
    {
        /* netdev_in is NULL here; look up by conn pointer. */
        ovs_mutex_lock(&myhw_mutex);
        struct myhw_ct_entry *e = myhw_find__(ctx->conn);

        if (e) {
            myhw_remove_ct_entry(e->hw_handle);
            hmap_remove(&myhw_ct_table, &e->hmap_node);
            free(e);
        }
        ovs_mutex_unlock(&myhw_mutex);
    }

Step 6: Declare the class
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    const struct ct_offload_class ct_offload_myhw_class = {
        .name             = "myhw",   /* must match dpif_offload_myhw_class.type */
        .init             = NULL,
        .batch_submit     = NULL,
        .conn_add         = myhw_conn_add,
        .conn_del         = myhw_conn_del,
        .conn_update      = myhw_conn_update,
        .conn_established = myhw_conn_established,
        .can_offload      = myhw_can_offload,
        .flush            = myhw_flush,
    };

Step 7: Register in the built-in list
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In ``lib/ct-offload.c``, add the new class to ``base_ct_offload_classes[]``::

    static const struct ct_offload_class *base_ct_offload_classes[] = {
        &ct_offload_dummy_class,
        &ct_offload_myhw_class,   /* add here */
    };

And declare the extern in ``lib/ct-offload.h``::

    extern const struct ct_offload_class ct_offload_myhw_class;

Signaling Hardware Handling Back to the dpif-offload Layer
-----------------------------------------------------------

When a connection is fully accelerated in hardware, subsequent packets for
that connection should bypass software conntrack.  This bypass is achieved
through the **flow offloading layer**, not through a direct feedback signal in
the ct-offload API.

The mechanism works as follows:

1. The first packet for a new connection causes an upcall.  OVS processes the
   packet through software conntrack (``conn_add`` fires), then installs a
   **datapath flow** that matches all subsequent packets for this 5-tuple.

2. The dpif-offload layer (``dpif_offload_class``) can push this datapath flow
   to hardware.  Once installed in hardware, matching packets are forwarded
   directly, never reaching the upcall handler or software conntrack again.

3. The ct-offload layer is responsible only for keeping the hardware CT table
   in sync: ``conn_add`` programs hardware CT state, ``conn_established``
   updates the reverse direction, ``conn_update`` extends the software expiry
   based on hardware activity, and ``conn_del`` cleans up.

In this model the ct-offload provider does not need to signal anything back
to the dpif-offload layer.  The two layers operate independently on the same
netdev.  The provider's dpif-offload implementation handles flow-rule
installation; the ct-offload implementation handles CT-state synchronization.

However, if the hardware CT engine can generate expiry events or last-used
interrupts, the provider should surface those as return values from
``conn_update``.  A non-zero return from ``conn_update`` causes OVS to refresh
the software expiry timer, preventing the software side from expiring a
connection that hardware is still actively forwarding.

Minimum Viable Implementation
------------------------------

To get a working provider with no hardware acceleration (useful for testing
the integration path), implement only the three mandatory callbacks and accept
all connections::

    static bool  myhw_can_offload(const struct ct_offload_ctx *ctx) { return true; }
    static int   myhw_conn_add(const struct ct_offload_ctx *ctx)    { return 0; }
    static void  myhw_conn_del(const struct ct_offload_ctx *ctx)    { }

    const struct ct_offload_class ct_offload_myhw_class = {
        .name        = "myhw",
        .can_offload = myhw_can_offload,
        .conn_add    = myhw_conn_add,
        .conn_del    = myhw_conn_del,
    };

Without ``conn_update``, software idle timers will expire connections
regardless of hardware activity.  Without ``conn_established``, the provider
never learns the reply-direction port.  A production implementation should
provide both.

Configuration
-------------

Conntrack offloading is enabled as part of the global hardware offload
configuration::

    ovs-vsctl set Open_vSwitch . other_config:hw-offload=true

No additional configuration is required.  The CT offload framework activates
automatically when ``hw-offload`` is set and a matching dpif offload class is
registered.  To disable, set ``hw-offload=false`` and restart OVS (the
enable path is a one-shot ``ovsthread_once``).

Testing
-------

The ``ct_offload_dummy_class`` (``lib/ct-offload-dummy.c``) is a complete
software-only reference implementation.  It records every lifecycle event and
exposes inspection helpers (``ct_offload_dummy_n_added()``,
``ct_offload_dummy_is_bidirectional()``, etc.) that unit tests use to verify
callback delivery.

The dummy class is registered automatically when the dummy dpif offload class
is active (``hw-offload=true`` with a dummy datapath), making it possible to
exercise the full ct-offload path in the OVS test suite without any hardware.
The unit tests in ``tests/library.at`` cover each individual callback, and the
integration test in ``tests/dpif-netdev.at`` verifies the end-to-end path
including bidirectional ``netdev_in`` propagation.

New providers should follow the same test structure: unit tests that call
``ct_offload_register()`` directly (bypassing the dpif-offload gate), and an
integration test that enables ``hw-offload`` with the real hardware type and
verifies each lifecycle event fires with the correct context.

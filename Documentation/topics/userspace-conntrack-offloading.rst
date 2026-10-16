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

=========================================
Userspace Datapath - Conntrack Offloading
=========================================

This document describes the conntrack offloading infrastructure in the OVS
userspace datapath, explains the design rationale, and provides a guide for
hardware vendors implementing a conntrack offload provider.

Overview
--------

Open vSwitch contains a userspace connection tracking (conntrack) engine
derived from the OpenBSD pf stack.  For every packet that carries a
``ct()`` action, OVS runs the packet through ``conntrack_execute()`` and
``process_one()``, which update connection state in software.

Modern hardware (SmartNICs, DPUs, and accelerator ASICs) often includes a
native CT engine that can track connection state and report last-used
timestamps without involving the host CPU.  The conntrack offload framework
(``ct_offload_class``) provides the lifecycle notifications that such
hardware needs to stay in sync with the OVS software CT table.

Architecture
------------

Conntrack offloading is deliberately kept separate from flow offloading
(``dpif_offload_class``).  The two layers serve different purposes:

* **Flow offloading** (``dpif_offload_class``): installs match/action rules
  in hardware: the equivalent of an ``rte_flow`` or TC flower rule.  After
  an upcall installs a datapath flow, the dpif-offload layer can push that
  rule to hardware so subsequent packets matching the same 5-tuple never
  cause a further upcall.

* **Conntrack offloading** (``ct_offload_class``): notifies hardware of
  connection lifecycle operations: new connections, bidirectional
  establishment, idle-timeout queries, and deletion.  Hardware uses these
  operations to maintain its own CT state tables, which may be separate
  from the hardware flow table.

The dpif-offload provider is the lead of the two layers: it owns the ports
and the hardware resources, and it decides whether conntrack offloading is
used at all.  A ct_offload class is registered globally, but it only
becomes active when the dpif-offload provider opens it (see `Registration
and Activation`_ below).  In practice the two providers are tightly
coupled and typically share access to the same hardware; the ct-offload
provider usually recovers its per-port offload state from the input netdev
(for example via ``netdev->dpif_offload``), and should verify with the
dpif-offload side that a port is actually being offloaded before accepting
a connection.  Information about which actions a flow offloads lives in
the dpif-offload layer, not in ct-offload.

Software conntrack always runs for the first packets of a new connection.
Once the hardware has been programmed (via the ADD and EST operations), the
provider's dpif-offload side installs a hardware flow rule that matches all
subsequent packets for the connection before OVS's software path, removing
them from the upcall / conntrack loop entirely.  The ct-offload operations
then serve two ongoing roles: UPD extends the software expiry timer when
hardware confirms the connection is still active, and DEL cleans up
hardware state when OVS decides to retire the connection.

Connection Lifecycle
--------------------

Operations are delivered to providers through ``batch_submit()``.  The
following state machine shows when each operation type fires and what the
provider is expected to do at each transition::

    packet arrives, ct(commit)
           |
           v
       [ ADD ]  -- hardware: allocate CT entry, store conn* -> handle map
           |
           |  ... forward packets flow through hardware ...
           |
           v
    reply packet seen, CS_ESTABLISHED | CS_REPLY_DIR
           |
           v
       [ EST ]  -- hardware: update CT entry with reply port;
           |                   set error to 0 once established in HW
           |
           |  if the provider sets error to EBUSY (establishment failed or
           |  was deferred), EST is retried on the next eligible reply
           |  packet
           |
           |  OVS expiry timer fires
           |
           v
       [ UPD ]  -- hardware: set last_used to the last-used time in ms
           |                   since epoch, or 0 if not offloaded here
           |
           |  a timestamp newer than the software view extends the
           |  connection's expiry; stale entries expire normally
           |
           v
    OVS decides to expire (or dpctl/flush-conntrack called)
           |
           v
       [ DEL ]  -- hardware: look up conn* -> handle map, remove CT entry

DEL is delivered for every tracked connection when the conntrack table is
flushed (``conn_clean()`` runs per connection), so there is no bulk flush
callback.

The framework tracks the outcome of each connection in a private slot and
exposes it via ``ct_offload_conn_is_tracked()`` (a provider accepted the
ADD op) and ``ct_offload_conn_established()`` (a provider confirmed
establishment in hardware).  The per-connection state, and therefore both
helpers, is visible in ``ovs-appctl dpctl/dump-conntrack`` output as an
``offloaded`` flag.

The ``ct_offload_ctx`` Structure
--------------------------------

Every operation carries a ``struct ct_offload_ctx`` with the following
fields:

``conn``
    Pointer to the OVS connection object.  Stable for the lifetime of the
    connection (from ADD through DEL).  Use this as the key in any internal
    ``conn* -> hardware_handle`` map.

``netdev_in``
    The input ``struct netdev *`` for the packet that triggered this
    operation.  Non-NULL at ADD (forward-direction input port) and at EST
    (reply-direction input port).  **NULL at DEL and UPD** - the provider
    must look up its hardware state by ``conn`` instead.

``input_port_id``
    ODP port number corresponding to ``netdev_in``.  Provided for
    convenience; the same information can be derived from ``netdev_in``.

``dir``
    The direction of the connection relative to the packet that triggered
    the operation.  A provider holding ``conn->lock`` can derive either
    direction's key via ``conn->key_node[dir].key``.

The ``ct_offload_class`` Interface
------------------------------------

A provider class consists of a name and five callbacks; all providers must
implement ``batch_submit()`` and ``might_offload()``, while ``init()``,
``open()``, and ``close()`` are optional:

``name``
    Unique provider name, for example ``"dummy"``.  Uniqueness is checked
    at registration time, and the dpif-offload provider uses this string
    when calling ``ct_offload_open()`` / ``ct_offload_close()``.

``init()``
    Optional one-time initialization called when the class is registered.
    It must not allocate per-port or per-instance hardware resources; that
    belongs in ``open()``.  Return 0 on success or a positive ``errno`` to
    abort registration.

``open()`` / ``close()``
    Optional activation callbacks.  ``open()`` is called through
    ``ct_offload_open()`` when a dpif-offload provider needs conntrack
    offload; ``close()`` runs through ``ct_offload_close()`` when the last
    opener releases it (opens are refcounted).  ``close()`` must undo
    whatever ``open()`` did.

``batch_submit(batch)``
    The only per-connection entry point.  Every operation - including
    single operations, which arrive as a batch of one - is delivered here.
    The provider examines each op's type, performs the operation (or
    declines it), and fills in the op's result fields (see below).
    Operations within a batch are independent: a failure on one op must
    not prevent processing the rest.

    Locking: the framework holds only ``ct_offload_rwlock`` (read side)
    across this call, and no ``conn->lock``.  A provider that accesses
    conn state, such as ``conn->private[]``, must acquire ``conn->lock``
    itself, and must not block for extended periods.

``might_offload(ctx)``
    Advisory pre-check called before the connection is committed.  Return
    false only when the provider is sure it will never handle this
    connection; because details such as the egress interface may not be
    known yet, the provider can still decline in the ADD op by setting
    ``error`` to ``EOPNOTSUPP``.  A typical implementation checks that
    ``ctx->netdev_in`` is a port serviced by its dpif-offload counterpart;
    see the dummy provider's use of ``is_dummy_netdev_class()``.

Operation types and result fields
---------------------------------

Each op in a batch has one of four types.  The framework initializes the
result fields to 0 before submitting, except for EST where ``error`` is
pre-set to ``EBUSY``:

``CT_OFFLOAD_OP_ADD``
    Program the connection into hardware.  Set ``error`` to 0 if accepted,
    ``EOPNOTSUPP`` if this provider does not handle the connection, or
    another positive ``errno`` on failure.

``CT_OFFLOAD_OP_DEL``
    Remove any offloaded state for the connection.  DEL is delivered even
    if the ADD op was declined or never issued; providers must tolerate
    unknown connections.  Set ``error`` to 0.

``CT_OFFLOAD_OP_UPD``
    Query hardware for the last-used time.  Set ``last_used`` to the time
    in milliseconds since epoch, or 0 if the connection is not offloaded
    in this provider or no timestamp is available.  Set ``error`` to 0.

``CT_OFFLOAD_OP_EST``
    The first reply-direction packet was seen; update hardware with the
    reverse-direction port.  Set ``error`` to 0 once the connection is
    fully established in hardware, or leave it at ``EBUSY`` if
    establishment failed or was deferred; EST will be retried on the next
    eligible reply packet while ``EBUSY`` is returned.

Registration and Activation
---------------------------

CT offload providers are registered globally at module initialization time
(``ct_offload_module_init()`` registers every class listed in
``base_ct_offload_classes[]`` in ``lib/ct-offload.c``).  Registration only
makes the class known to the framework; it does not activate it.

Activation is controlled by the dpif-offload provider that owns the ports
and hardware resources::

    ovs-vsctl set Open_vSwitch . other_config:hw-offload=true
        |
        v
    dpif_offload_module_init()      [first call only]
        registers all base dpif_offload_class entries and all base
        ct_offload_class entries (including "dummy")
        |
        v
    dpif attaches a datapath, dpif-offload provider opens its class
        |
        v
    dpif-offload provider's open() callback
        calls ct_offload_open("<name>") for the CT offload provider
        it wants active for its ports  [refcounted]
        |
        v
    dpif detaches / offload disabled
        provider's close() calls ct_offload_close("<name>")

This mirrors the init/open/close split of ``struct dpif_offload_class``.
It allows a dpif-offload provider to disable conntrack offloading for its
ports even when flow offloading is active, and it allows one ct_offload
class to be shared by multiple offload providers (opens are refcounted,
and ``close()`` runs when the last user releases it).

For a new hardware provider ``myhw``, this means:

* Set ``dpif_offload_class.type = "myhw"`` and add it to
  ``base_dpif_offload_classes[]`` in ``lib/dpif-offload.c``.
* Set ``ct_offload_class.name = "myhw"`` and add the class to
  ``base_ct_offload_classes[]`` in ``lib/ct-offload.c``.
* Call ``ct_offload_open("myhw")`` from the dpif-offload provider's
  ``open()`` callback, and ``ct_offload_close("myhw")`` from its
  ``close()`` callback.

Implementing a New Provider
----------------------------

The dummy provider (``lib/ct-offload-dummy.c``) is a complete,
software-only reference implementation: it maintains a ``conn* -> entry``
list, implements ``batch_submit()`` and ``might_offload()``, logs every
operation at debug level, bumps coverage counters, and is opened/closed by
the dummy dpif-offload provider.  New providers should mirror its
structure; the essentials are::

    static void
    myhw_batch_submit(struct ct_offload_op_batch *batch)
    {
        struct ct_offload_op *op;

        CT_OFFLOAD_BATCH_OP_FOR_EACH (batch, i, op) {
            switch (op->type) {
            case CT_OFFLOAD_OP_ADD:
                op->error = myhw_add(op);     /* 0 / EOPNOTSUPP / errno */
                break;
            case CT_OFFLOAD_OP_EST:
                if (myhw_est(op)) {
                    op->error = 0;            /* established in hardware */
                }
                break;                        /* else leave it at EBUSY */
            case CT_OFFLOAD_OP_UPD:
                op->last_used = myhw_last_used(op->ctx.conn);
                break;
            case CT_OFFLOAD_OP_DEL:
                myhw_del(op->ctx.conn);       /* tolerate unknown conns */
                break;
            }
        }
    }

    const struct ct_offload_class ct_offload_myhw_class = {
        .name         = "myhw",   /* must match the dpif_offload class type */
        .batch_submit = myhw_batch_submit,
        .might_offload = myhw_might_offload,
    };

Where ``myhw_might_offload()`` checks that ``ctx->netdev_in`` is a port its
dpif-offload counterpart services (the dummy provider uses
``is_dummy_netdev_class(netdev_get_class(ctx->netdev_in))`` for this), and
the op handlers key all state on ``op->ctx.conn``, since ``netdev_in`` is
NULL at UPD and DEL.

Signaling Hardware Handling Back to the dpif-offload Layer
-----------------------------------------------------------

When a connection is fully accelerated in hardware, subsequent packets for
that connection should bypass software conntrack.  This bypass is achieved
through the **flow offloading layer**, not through a direct feedback signal
in the ct-offload API.

The mechanism works as follows:

1. The first packet for a new connection causes an upcall.  OVS processes
   the packet through software conntrack (the ADD op fires), then installs
   a **datapath flow** that matches all subsequent packets for this
   5-tuple.

2. The dpif-offload layer pushes this datapath flow to hardware.  Once
   installed, matching packets are forwarded directly, never reaching the
   upcall handler or software conntrack again.

3. The ct-offload layer is responsible only for keeping the hardware CT
   table in sync: ADD programs hardware CT state, EST updates the reverse
   direction, UPD extends the software expiry based on hardware activity,
   and DEL cleans up.

If the hardware CT engine can report last-used timestamps or expiry events,
the provider surfaces them through ``last_used`` on UPD ops.  The framework
advances the connection's software expiry only by how much newer the
hardware timestamp is than the one already accounted for, so stale hardware
entries expire normally instead of being extended forever.

Configuration
-------------

Conntrack offloading is enabled as part of the global hardware offload
configuration::

    ovs-vsctl set Open_vSwitch . other_config:hw-offload=true

No additional configuration is required.  A CT offload provider becomes
active when its dpif-offload counterpart opens it, which happens when a
datapath using that provider is attached with ``hw-offload`` enabled.  To
disable, set ``hw-offload=false`` and restart OVS (the enable path is a
one-shot ``ovsthread_once``).

Testing
-------

The dummy class makes it possible to exercise the full ct-offload path in
the OVS test suite without any hardware.  The system test
``dpif-netdev - conntrack offload dummy`` in ``tests/dpif-netdev.at`` runs
real traffic through a dummy datapath with ``hw-offload=true`` and checks:

* the provider's debug log lines (``conn add`` / ``conn established`` /
  ``conn del``, including propagation of the ingress netdev name in each
  direction);
* the provider's coverage counters via ``ovs-appctl coverage/show``;
* the ``offloaded`` flag in ``ovs-appctl dpctl/dump-conntrack``;
* the per-flow offload state in ``ovs-appctl dpctl/dump-flows``.

New providers should follow the same pattern: an integration test that
enables ``hw-offload`` with the real hardware type and verifies each
lifecycle operation fires with the correct context.

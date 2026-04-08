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
Userspace Datapath - Conntrack offloading
=========================================

This document explains the internals of the Open vSwitch userspace connection
tracking offloading.

Design
------

Open vSwitch provides a modified BSD stack based connection tracking facility
which primarily processes packet-at-a-time into various state updates.
This runs inline with the pmd execution pipeline through the
`conntrack_execute` into the `process_one` call.

The core of the offload mechanism is the `ct_offload_class` structure. This
structure defines the callbacks for offload providers, allowing them to
register for specific connection tracking events.  Each offload provider
instance is placed in a list in priority order, and each one is called during
operation processing.  There is a single bulked operations interface, but it
currently is limited to calling into each ops list facility-at-a-time.

All offload is done under a large `ct_offload` lock to keep the offload
provider list coherent.

Primary Connection Events
-------------------------

The offload provider handles specific events corresponding to the lifecycle of
a connection. These are call-ins provided by the `ct_offload_class` structure.

* Connection Add (conn_add) is triggered when a connection is created and
  committed to the connection list.
  When triggered, the provider receives the conn_add event to initialize
  tracking for the new connection.
* Connection Delete (conn_del) is triggered when a connection is removed.
  The provider receives the conn_del event to clean up resources.
* Connection Established (conn_established)
  This is a special event that occurs exactly once when the first
  reply-direction packet is seen for an offloaded connection.
  The netdev_in will contain the reply netdev. The offload provider should
  have access to the initial netdev from the conn_add and the reply direction
  from the conn_established events. This allows the provider to track both
  sides of the connection.
* Connection Update (conn_update) is called when the connection tracking (ct)
  expiration timer is set to run expiration processing for a connection.
  It asks for an update on the packet list. It returns the last-used timestamp
  in milliseconds since epoch, or 0 on failure.

Configuration
-------------
Conntrack offload is configured as part of dpif offloading for userspace. It
utilizes the same configuration knob to enable offloading features.

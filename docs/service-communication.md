# Service communication

For developers and Windows administrators, this page maps the installed
services' network endpoints and BGP actions. See
[Security, authentication, and build hardening](security.md) for privilege levels,
authentication checks, and the ASCII and rendered draw.io diagrams.

## Runtime flow

The two executables run in separate processes:

1. `BfdWinService` receives and validates UDP packets, updates session state and
   timers, and sends configured BFD or S-BFD packets. It runs as LocalService.
2. When `BgpPeerName` is configured, its BGP worker sends fixed `Get`, `Start`, or
   `Stop` requests on `\\.\pipe\BfdWinService.Bgp.v1`. The client verifies the
   broker's SCM process ID, and the broker checks the BFD client's Windows token.
3. `BfdBgpBroker` runs as LocalSystem and invokes native Management Infrastructure
   (MI) against the local `PS_BgpPeer` Windows provider for one target read from
   protected Parameters. It returns status/error replies to the BFD client.
4. Windows RRAS manages the BGP connection to the remote peer.

Packet processing, logging, and the optional BGP worker keep the BFD process
identity. The broker has its own logging queue. Both services write Operational
events and report lifecycle status to SCM; BFD can also write a configured file
log. See [Configuration, lifecycle, and logs](security.md#configuration-lifecycle-and-logs)
for those paths and [diagnostic access permissions](security.md#e-service-control-configuration-and-diagnostic-access)
for administrative control and read-only monitoring.

## Administrative status queries

The LocalService BFD process also hosts the read-only
`BfdWinService.Status.1` COM Automation endpoint. Local elevated Administrators
and SYSTEM can call `GetSnapshot()` to obtain an immutable observation of session
state, peer identity, active timing, communication timestamps, and packet/error
counters. COM activation targets the installed SCM service, and status queries
do not contact the BGP broker or provider.

The engine replaces its published `Arc` at most once per second. COM query
threads read that snapshot without requesting work from, or holding a lock on,
the packet loop. Each returned object retains its values even after later
publications; repeat `GetSnapshot()` for a later observation. Session data can
lag BFD detection and peer reports preserve their last accepted values.

Activation and call permissions grant local SYSTEM and enabled Administrators
only. The endpoint checks caller identity on class creation and dispatch, and
rejects remote calls. It has no mutation methods or secret authentication data.
Use Windows service queries for lifecycle status. See
[Query a session snapshot](monitoring.md#query-a-session-snapshot) for PowerShell
examples and [Administrative COM status access](security.md#administrative-com-status-access)
for activation registration and caller checks.

## UDP inputs and outputs

The selected role determines the socket endpoints. `P` and `Q` denote the local
and peer stable source ports, respectively, each in 49152-65535. The port
numbers can differ. Outgoing TTL/hop limit is 255.

| Role | Outgoing packet | Incoming packet | Receive TTL/hop limit |
| --- | --- | --- | --- |
| Classical single-hop | local:P -> peer:3784 | peer:Q -> local:3784 | Exactly 255 |
| Classical multihop | local:P -> peer:4784 | peer:Q -> local:4784 | Required metadata; `MinTtl` threshold if configured |
| S-BFD initiator | local:P -> reflector:7784 | reflector:7784 -> local:P | Required metadata; `MinTtl` threshold if configured |
| S-BFD reflector | local:7784 -> initiator's source port | initiator's source port -> local:7784 | Required metadata; `MinTtl` threshold if configured |

Classical point-to-point mode identifies the peer by its configured link and
discriminator rather than requiring a fixed source IP. S-BFD uses configured
peer/allowed-source rules. The reflector's runtime accepts nonzero source ports
other than 7784; the installed firewall limits requests to 49152-65535.

## BGP behavior

BGP control runs only when `BgpPeerName` is configured for classical BFD or an
S-BFD initiator. Reflectors reject BGP control. Plain BFD still has the installed
SCM dependency on the broker, but starts no BGP worker and makes no pipe probe.

Startup reads BGP status without changing the peer. Entering Up requests Start
if needed; Down after the session has established requests Stop. Peer AdminDown
or an administrative service stop withdraws the controller's own latest Stop
with Start when needed. Crashes and pipe disconnections do not themselves stop
the BGP peer.

The final RRAS-to-remote-peer link represents Windows-managed BGP behavior.
This repository invokes the local management provider; it does not implement
the BGP connection or configure its wire authentication. The actual RRAS
process token and deployed provider/channel ACLs require host inspection.

For implementation locations, see the [security source map](security.md#source-map).

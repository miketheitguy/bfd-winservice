# Develop the Rust library and service boundaries

Turtle power starts with clear owners, dude. This reference is for Rust
maintainers changing library APIs, the engine, or native service boundaries.
See [validation](validation.md) for the required checkout checks.

## Use the Rust configuration and error APIs

Keep ownership totally tubular and follow the validated API. `Options` contains
mutable provisioning input. Call `Options::into_validated()` to produce an
immutable `ValidatedOptions` snapshot. Sweet: validation gives startup settings
a stable home. On Windows, `config::load_registry()` returns this snapshot
directly. Clones share its storage, and `ProtocolRole` carries the required
nonzero initiator or reflector discriminator.

Use `Engine::from_config`, `Session::from_config`, `Reflector::from_config`, and
`Transport::from_config` to reuse a snapshot without repeating validation.
The constructors that accept raw `Options` still validate before use.
Live S-BFD timers and maintenance state are separate from startup settings.

`Session::set_timing` rejects overlapping transmitted Poll changes with
`ConfigError::PollInProgress`. Wait for the Final and a subsequent non-Final
response before another wire timer change. An Up TX increase is advertised in
the Poll but takes effect only after its Final. See the
[S-BFD timing reference](../seamless.md#change-timing-and-entity-availability).

`Session::packet` and `packet_at` are convenience APIs that register a
transmission when they return bytes. Library callers using these
APIs must deliver the returned packets. The Windows runtime prepares packets
without mutation and commits sequence, Poll, and probe tracking only after a
successful socket send; failed sends don't consume meticulous sequences.
Classical keyed SHA1 can reuse its last transmitted packet; see
[digest reuse and sequence policy](../security/authentication-performance.md#hash-cost-and-sequence-frequency).

The runtime encodes packets into fixed 52-byte storage, reuses its receive
buffer, and verifies keyed authentication without copying the packet or
allocating a digest. The public packet convenience APIs still return owned
vectors. Use `Transport::receive_into` with a retained `Datagram` to reuse
receive storage in library code.

Use `Engine::run_until` with a cloneable `runtime::StopSignal` to wait for socket
events, protocol deadlines, and shutdown. Service control and console handlers
call `StopSignal::signal` to wake the engine immediately. `Engine::run` remains
available for callers with a channel receiver; it checks that channel every
10 milliseconds while idle.

Configuration errors use `error::ConfigError`. Packet and transport rejection
uses `error::PacketError`; authentication uses `error::AuthError`.
`session::ReceiveError` distinguishes packet and authentication failures. Match
these enums rather than comparing their display strings. Error messages omit
keys and packet contents.

`Session::remote_state()` and `remote_diagnostic()` expose the last accepted
peer report, including reserved diagnostic values. They update only after
packet and authentication validation. Peer diagnostics don't replace LocalDiag.
The runtime tracks one peer report per discriminator and communication period
to suppress repeated state and diagnostic events. See the
[Operational event reference](../logging.md#operational-events).

For logger construction, shared-worker ownership, flush completion, and queue
loss APIs, see [Logging internals](../reference/logging-internals.md#library-api).
Keep blocking flushes out of the protocol timer loop, dude.

## Raw options, encoding, and registry loading

`Options::new` creates defaults without validating. Raw `Options` stay mutable;
consume them into a fresh validated snapshot after changing them.
`ControlPacket::encode` serializes public header fields without validating;
decoding and authentication verification supply receive-side checks.

The Windows registry loader is read-only. It enforces value types, numeric
narrowing, Boolean ranges, and valid UTF-16, omits authentication contents from
errors, and returns validated settings before sockets open. Native loader tests
use unique temporary HKCU keys, leaving installed configuration alone. For
registry names and defaults, use the [configuration reference](../configuration.md).

## Initialize broker management security

The BFD service sends fixed-target BGP requests through authenticated Windows
local RPC (`ncalrpc`). See [Security, authentication, and build hardening](../security.md)
for caller and server identity checks, and [Monitor service status and BFD
events](../monitoring.md) for lifecycle queries and event-log monitoring.

`src/bgp_broker/com.rs` is private to the broker. Its dedicated MTA thread
initializes explicit process security before native MI starts and remains alive
until provider work finishes. Incoming COM access is local-only and grants only
SYSTEM. Normal shutdown, startup errors, and unwinding join
the owner thread, which calls `CoUninitialize`.

The Rust suite isolates process-wide COM security tests in child processes. It
checks duplicate initialization and rejects preexisting security defaults. The
release workflow also runs a read-only native MI schema query under this policy
to check compatibility with Windows management providers. In-process state
observers remain available to library users and UDP integration tests.

## Maintain the private local RPC interface

Ninja discipline, dude: keep the service boundaries clear. `src/local_rpc.rs`
hosts the private BFD interface. Its `GetSessionStatusV1` operation copies one
published snapshot on an RPC worker. The broker queries it from one supervised
worker inside its existing process; it launches no helper. Keep this path in its
own lane, dude, separate from the BGP control RPC interface and COM/MI provider
worker. The BGP interface in `src/bgp/ipc.rs` shares the telemetry interface's
binding, registration, and Authz helpers, with server/caller identities
reversed. Both channels also require their expected service SID in any nonempty
caller restricting list, including for write-restricted tokens. Its bounded
control queue sends work to the serialized provider worker; RPC callbacks never
execute MI operations. The contracts are `rpc/bfd_local.idl` and
`rpc/bgp_control.idl`.

Preserve the conditional server identity policy, exact caller account and
service SID checks, Identify credentials, packet privacy, and management denial.
The provider process keeps its existing token and COM/MI policy. Never vary the
BFD identity policy or treat a unique binding as an authorization-cache reset.

The record uses only fixed-width integers across FFI. Native robust stubs apply
IDL ranges; `src/local_rpc/status.rs` converts into Rust types once. There is no
validation dependency. Invalid data clears the cache and retries with capped
backoff, as do connection failures; only a stuck native worker quarantines
telemetry. These paths do not change BGP state. Keep packet-loop
publication independent of query count and retain pending native storage until
completion. A stuck worker must not block provider work or service shutdown.

See [RPC session-status query](../rpc-session-status-design.md),
[RPC authentication](../rpc-authentication.md), and
[Service communication](../service-communication.md).

For commands and prerequisites, follow [native RPC validation](validation.md#verify-native-rpc-boundaries).
The opt-in coexistence fixtures exercise real read-only CIM schema traffic
alongside RPC, including replacement-server rejection and recovery. Fixture
processes isolate registrations and identities; they are not the production
architecture. See [RPC verification scope](../security/local-rpc.md#verify-the-implementation)
for the separate installed-token checks.

## S-BFD library timing APIs

Library callers can use `Timing::new`, `Session::set_timing`,
`Engine::set_timing`, and `Reflector::set_timing` without registry access.
For an Up initiator, changes to `MinTxUs` or `DetectMult` return
`ConfigError::PollInProgress` while a transmitted Poll or its separation period
protects a preceding change. A `MinRxUs`-only RTT allowance change doesn't alter
wire parameters and can apply during that period. Reflectors apply their
stateless response settings immediately.

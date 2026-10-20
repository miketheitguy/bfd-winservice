# RPC session-status query

For Rust maintainers and Windows administrators, this reference describes the
implemented broker-to-BFD status call, its accepted data ranges, and the broker's
response to invalid data. The client runs on a worker thread inside
`bfd-bgp-broker.exe`. The authenticated local RPC connection carries the reply
directly; there is no helper process, stdout transport, or additional named pipe.
For Windows identity checks, see [RPC authentication](rpc-authentication.md).

A valid reply still needs freshness receipts: check `BrokerStatus::is_fresh()`
before treating a cached observation as current.

For operator commands, see [Monitor service status and BFD events](monitoring.md).
To look up this contract, start with [Session fields](#session-fields) and
[Native and Rust bounds](#native-and-rust-bounds). To assess an observation, see
[Broker cache and freshness](#broker-cache-and-freshness) and
[Secure response to invalid data](#secure-response-to-invalid-data).

## Function call and ownership

Inside a broker worker function returning `Result`, fetch one observation with:

```rust
let status = bfd_winservice::local_rpc::query_bfd_session_status()?;
```

The function returns `Result<SessionStatus, SessionStatusQueryError>`. It checks
the broker's own SYSTEM account and service SID, uses one fixed BFD server
identity policy, and converts a successful reply into Rust domain types before
returning it. Only one production client call can be in flight. Concurrent
attempts return busy rather than queueing work.

### Native interface contract

The native contract in [bfd_local.idl](../rpc/bfd_local.idl) is:

```idl
unsigned long GetSessionStatusV1(
    [in] handle_t binding,
    [out, ref] BFD_SESSION_STATUS_V1 *status);
```

Interface `BfdLocal` version `2.0` defines only this operation, at operation
number `0`. It uses UUID `8d10db9d-8aa1-4bd2-bcb6-0bc2e5597319` and endpoint
`BfdWinService.Local.v2`. There is one configured session per BFD process, so
the call accepts no session ID, filter, output length, or configuration.
Application and native failures return errors; the client does not interpret a
failed call's output record.

The native record is fixed-size: its x64 C/Rust layout is **336 bytes**, with no
strings, variable-length arrays, application pointers, packet contents, or keys.
Generated stubs own NDR marshaling. Raw Rust memory is never an IPC format.
Native layout tests check size, alignment, and field offsets against MIDL output.

### Deploy matching binaries

Deploy the BFD service and broker binaries together. Version `2.0` exposes only
`GetSessionStatusV1`, moving it from operation number `1` in version `1.1` to `0`.
The major interface version and endpoint change
prevent mixed binaries from interpreting a call as the wrong operation. There
is no legacy endpoint fallback. The `BFD_SESSION_STATUS_V1` record
remains schema version `1`; the interface version is a separate contract.

The BGP control interface stays at `BgpControl` version `1.0`. Its BFD-to-broker
liveness operation verifies control authorization and detects broker restarts;
the broker-to-BFD telemetry query does not replace it.

## Session fields

The typed `SessionStatus` contains these observations:

| Field group | Meaning |
| --- | --- |
| `engine_instance_id`, `publication_sequence` | Nonzero engine instance and publication identifiers. Compare sequence values for equality within an instance; publications wrap without using zero. Counter history belongs to the instance. |
| `captured_at_utc`, `engine_uptime`, `snapshot_age` | UTC engine capture time and monotonic durations measured when the server reads the snapshot. |
| `session_type`, `transport_mode` | Classical, S-BFD initiator, or stateless reflector role, and the configured transport profile. |
| `local_state`, `peer_state` | Local state at publication and optional last accepted peer report. Peer state can remain historical after detection expiry. |
| `local_diagnostic`, `peer_diagnostic`, `communicating` | Typed local diagnostic, optional five-bit peer diagnostic, and optional communication status at publication. |
| `last_valid_receive`, `last_successful_send` | Optional `(SystemTime, Duration)` pairs: UTC event time and monotonic event age at the RPC read. A successful send does not prove peer reception. |
| `state_since_utc`, `last_up_utc`, `last_down` | Current-state start and optional transition history. `last_down` includes its diagnostic. |
| `local_address`, `peer_address`, `last_accepted_source`, `control_port`, `interface_index` | Bound source endpoint, optional configured peer, optional actual received source, control/listen port, and optional interface index. IPv6 source scope is preserved. |
| `local_discriminator`, `remote_discriminator` | Nonzero local identifier and optional active remote identifier. A historical peer report does not imply the remote identifier is still active. |
| `effective_tx_interval`, `detection_time`, `local_detect_multiplier`, `peer_detect_multiplier` | Optional role-appropriate timing and nonzero multipliers. |
| Packet/error/transition counters | Accepted receives, successful sends, rejections, authentication failures, socket errors, detection expiries, and transitions to Up. Counters saturate at `u64::MAX`. |

Rejected or unauthenticated packets do not refresh the accepted receive time.
Before reception, receive/peer fields are absent. A stateless reflector has no
peer session, communication window, or detection timer; those fields stay absent.
Local `Down`, historical peer `Up`, and `communicating = false` are valid together.
The client preserves these observations instead of forcing them into agreement.

## Native and Rust bounds

MIDL `/robust` stubs enforce the declared integer ranges. Rust constructs the
typed result once through `TryFrom`, enum matches, `NonZero` types, address
constructors, and checked time arithmetic. No validation crate or separate
post-construction validation pass is used. Microsoft describes native range
checks in [the MIDL range attribute](https://learn.microsoft.com/en-us/windows/win32/midl/range);
Rust describes fallible conversion in [TryFrom](https://doc.rust-lang.org/std/convert/trait.TryFrom.html).

The successful V1 record accepts these values:

| Data | Accepted representation |
| --- | --- |
| Schema | Version `1`, native record size `336`, only the 13 defined presence bits, and zero data for absent fields |
| Role/mode/state/Boolean | Role `0..=2`; mode `0..=1`; BFD state `0..=3`; Boolean `0` or `1`, converted to Rust enums/`bool` |
| Diagnostics | Local/last-down `0`, `1`, `3`, or `7`; peer `0..=31`, including reserved peer values |
| Identifiers | Nonzero `u128` engine ID, `u64` publication ID, and `u32` discriminators/interface index when present |
| Ports/multipliers | Nonzero `u16` port and `u8` multiplier when present |
| Addresses | IPv4 or IPv6; IPv4 has zero unused bytes and scope; IPv6 scope is `u32` |
| TX/detection durations | Microseconds in `0..=u32::MAX` for TX and `0..=u32::MAX × 256` for detection; zero can represent initial detection parameters before a peer report |
| Uptime/ages | At most 100 × 366 days; snapshot age does not exceed uptime; event ages lie between snapshot age and uptime |
| UTC timestamps | FILETIME ticks `1..=2650467743999999999`, covering the supported 1601–9999 calendar range; conversion uses checked arithmetic |
| Counters | Full `u64` range, including saturation; no arbitrary smaller cap |

UTC ordering is not used as a validity or freshness test: clock corrections can
move later wall-clock observations backward. Optional times use presence bits,
not a guessed zero-date convention. Reflector-inapplicable fields are absent.
Unknown schema, enum, presence-bit, or local diagnostic values are rejected
rather than clamped, transmuted, or mapped to a default state.

## Snapshot coherence and packet isolation

BFD's engine exclusively owns mutable session state. It updates scalar telemetry
and existing monotonic samples during packet processing. Changed publications
have a 100-millisecond minimum spacing; unchanged refresh targets one second.
Scheduling can delay either publication. The capture metadata, instance,
sequence, and event instants belong
to the same immutable publication as the protocol values.

During startup, BFD gives RPC `Engine::status_observer()` before moving the engine
to its worker. The RPC manager repeats authorization, obtains a nonblocking
status-manager permit, loads one `Arc`, and copies its selected fields. Four
status managers can run concurrently; excess calls return busy. The manager
releases the snapshot before native marshaling. It never requests engine work,
wakes the packet loop, acquires an engine lock, or changes publication frequency.

Do not merge `StateObserver`'s immediate atomic state with an older detailed
snapshot: that can combine observations that never existed together. ArcSwap's
[single-load consistency guidance](https://docs.rs/arc-swap/latest/arc_swap/struct.ArcSwapAny.html#method.load)
supports reading one immutable view per operation.

Scheduled snapshot allocation and reclamation remain on the engine's
publication path. ArcSwap is lock-free, not a hard elapsed-time guarantee. See
[ArcSwap performance](https://docs.rs/arc-swap/1.9.2/arc_swap/docs/performance/index.html).
Readers cannot request extra publications. A stalled or delayed engine can
therefore produce valid telemetry that fails the broker's freshness policy.

## Broker cache and freshness

The broker starts its supervisor and single RPC worker after reporting SCM
Running, avoiding a dependency cycle with BFD. Successful queries repeat once
per second, independently of the provider worker and packet publication interval.

### Cache states

`cached_bfd_session_status()` returns the current `Arc<BrokerStatus>`, or `None`
before the monitor starts. `BrokerStatus` distinguishes `Unavailable`,
`Available`, and `Quarantined`. An `Available` value contains only converted
`SessionStatus`, its broker receipt time, and total fetch duration. Call
`is_fresh()` before treating it as current.

### Freshness calculation

The conservative age adds the server's snapshot age, the entire fetch duration,
and monotonic time since receipt. Above two seconds, `is_fresh()` returns false;
valid stale data remains available for diagnosis. This monitoring threshold is
not the BFD detection timer. Snapshot publication cadence is nominal under normal
scheduling, not a maximum age. RPC success and SCM Running do not imply Up.

## Secure response to invalid data

The broker applies these failure policies:

| Condition | Cache and recovery | Provider behavior |
| --- | --- | --- |
| Valid fresh reply | Publish typed result; reset retry history | Unchanged |
| Valid stale reply | Retain for diagnosis; freshness is false; reset retry history and continue polling | No fabricated state or BGP action |
| Connection, authentication, busy, unavailable, or completed deadline failure | Clear previous cache to `Unavailable`; retry with backoff; informational report at most once per minute | Continue existing fixed-target control; never weaken authentication |
| Invalid record or safely reported native unmarshaling/range error | Discard the complete record; clear prior cache to `Unavailable`; retry with backoff; Error 301 at most once per minute | Keep broker Running; no automatic BGP action or restart |
| Native worker exceeds eight-second supervision budget | Quarantine telemetry and retain that single owned worker; no replacement worker loop | Provider and shutdown remain responsive |
| Fatal native exception or detected process memory corruption | Do not convert to a recoverable query error; let the process terminate | Continuing in possibly corrupted process memory is unsafe |

### Retry and reporting policy

Consecutive failed queries wait 1, 2, 4, 8, 16, then 30 seconds, remaining at
30 seconds until a valid reply resets the delay. A valid reply, including stale
telemetry, restores one-second polling. Stop interrupts every backoff wait.
Rejected-data and ordinary failure reports have independent one-minute limits;
successful replies do not reset those reporting limits.

Malformed telemetry is not converted into `Down`, partially salvaged, or used to
select a provider target. Stopping or automatically restarting the broker would
let a bad status response disrupt its otherwise independent provider role and
dependent service lifecycle. A clean rejection is not evidence that broker
memory has been corrupted and does not require permanent quarantine. Investigate
repeated rejection categories, matching binaries, clock validity, and BFD/host
errors; successful replies recover automatically.

### Injection and Rust's safety boundary

An unrelated process cannot normally supply a reply: the client pins the BFD
account and service SID, and local RPC protects the exchange against modification
in transit. Authentication establishes the source, not the truth of its data.
A compromised authorized service can return invalid or valid-but-false values.
A remote BFD peer influences protocol observations through accepted packets;
it does not supply the RPC record directly. See
[the Windows identity checks](rpc-authentication.md#server-identity-checks).

Only integers and fixed arrays cross the Rust FFI boundary. Checked conversion
constructs enums, Booleans, nonzero values, and times afterward. Rust does not
automatically validate foreign memory; an invalid Rust enum or Boolean would
itself violate [Rust's validity rules](https://doc.rust-lang.org/reference/behavior-considered-undefined.html).
The native stubs and C wrapper execute outside safe Rust's guarantees. Neither
quarantine nor range checks can contain actual corruption of their shared
process memory or detect plausible lies from an authenticated service.

The wrapper uses
[RpcExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcexceptionfilter)
to report recoverable RPC exceptions while leaving fatal native faults, including
access violations and stack corruption, outside its error handler. Quarantine
is reserved for a worker that cannot finish or release its native ownership;
it prevents further calls and resource accumulation, not malicious-data injection.

## Cancellation and shutdown

Asynchronous bind and call deadlines are two seconds each. Abortive cancellation
still waits for native completion before releasing buffers, output, events,
binding, or security allocations. `RPC_C_OPT_CALL_TIMEOUT` is ignored for LRPC;
it is not the deadline mechanism.

The supervisor waits at most eight seconds for a fetch. If native ownership
cannot be resolved, the one worker retains its stack and native allocations
until completion or process exit. The supervisor quarantines telemetry and
starts no replacement. Broker shutdown joins the supervisor but never waits
indefinitely for or forcibly terminates that worker. Ordinary query failures do
not abort the provider process.

### BFD server shutdown

BFD closes its observer when packet processing ends, before announcements and
BGP cleanup. It then unregisters and drains its RPC interface before releasing
the descriptor. A previously loaded snapshot remains
safe to read; its existence does not imply the engine is still running.

## Verification and source map

Run the native RPC suite and explicit read-only MI coexistence test on a Windows
host with a normal token:

```powershell
cargo test-release --lib local_rpc::
cargo test-release --lib native_provider_traffic_preserves_fixed_rpc_policy_and_replacement_rejection -- --ignored
```

### Test coverage and limits

Tests cover C/Rust layout, native range rejection, Rust schema/type conversion,
historical peer state, saturation, reflector absence, stale caching, invalid-data
recovery on the same worker, capped backoff and reset, cancellation, and
nonblocking shutdown during both retry waits and native-worker quarantine.
The coexistence test uses real CIM schema traffic, fixed-policy RPC, replacement
server rejection, and recovery in the same process. It performs no BGP mutation.
Fixture processes isolate test identities and RPC registration, not production
calls. Installed SCM tokens still require the separate MSI first-start/repair test.

### Implementation files

The implementation lives in these files:

- [Status conversion](../src/local_rpc/status.rs)
- [RPC registration/client](../src/local_rpc.rs)
- [Broker supervision/cache](../src/local_rpc/monitor.rs)
- [Snapshot publication](../src/runtime/status.rs)
- [Native completion](../rpc/client.c)

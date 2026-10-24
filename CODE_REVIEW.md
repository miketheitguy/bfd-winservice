# Code review checklist

Cowabunga, review crew. Use this checklist when reviewing BFD changes. Verify
each claim against the code and the relevant tests; record findings with their
source locations and practical impact. Apply the user-installed `$rust-skills`
guidance and its referenced rules, giving memory safety, borrowing, ownership,
and native lifetimes priority. See [Agent skills](AGENTS.md#agent-skills).

## Configuration and authentication keys

- Validate addresses, roles, timing, numeric narrowing, and option combinations
  before sockets open or the service reports Running.
- Keep validated configuration immutable and separate live S-BFD timing from
  startup settings.
- Read only bounded `REG_BINARY` ciphertext from `Parameters\Secrets` for
  registry-backed authentication. Reject failed decryption and invalid keys.
- Match DPAPI allocations with `LocalFree` and wipe plaintext before release.
  Keep keys out of logs, error messages, and public telemetry.
- Check that key provisioning verifies persisted ciphertext, restores the
  previous encrypted value on failure, and changes only `AuthKeyDpapi`.

See [configuration](docs/configuration.md), [packet authentication](docs/security/packet-authentication.md),
and [library APIs](docs/development/library.md).

## Packet and session boundaries

- Preserve transport, structural, discriminator, and authentication checks
  before accepted state, timers, and sequence tracking change.
- Check sequence wraparound, Poll/Final ownership, timer arithmetic, backoff,
  and successful-send commitment.
- Keep packet processing responsive under floods and output pressure.
- Preserve the role-specific behavior of classical sessions, S-BFD initiators,
  and stateless reflectors.

Use the [protocol reference](docs/protocol.md) and
[RFC test mapping](docs/rfc-conformance.md).

## Windows identity and native ownership

- Verify each service's account, enabled service SID, required restrictions,
  and exact privilege set before accepting work.
- Keep service-specific grants on configuration, Secrets, RPC, and log objects.
- Pin the server identity and authorize the exact caller on every private RPC
  call without attaching caller tokens to threads.
- Check FFI layout, initialization, lengths, alignment, allocator ownership,
  callback lifetime, cancellation, and final native completion.
- Preserve the broker's own identity and COM/MI policy for provider operations.
  Keep telemetry failures separate from BGP control decisions.

See [service isolation](docs/security/service-isolation.md),
[local RPC security](docs/security/local-rpc.md),
[status conversion](docs/rpc-session-status-design.md), and
[provider ownership](docs/reference/bgp-provider.md).

## Lifecycle, installation, and verification

- Bound startup readiness, retry queues, output queues, cleanup, and shutdown.
- Preserve fixed-target BGP actions and administrative release of BFD's Stop.
- Keep services stopped until installer security provisioning completes.
- Verify rollback and repair preserve administrator settings, encrypted keys,
  SCM policy, and required protected ACLs.
- Inspect production executable hardening separately from test profiles.
- Update the canonical documentation and run the checks appropriate to the
  change. Report any unrun installed-service or interoperability checks.

Follow [development validation](docs/development/validation.md) and
[packaging checks](docs/development/packaging.md) for commands and prerequisites.

# Implementation source map

Follow the code trail before the pizza break. For the code receipts, these files
implement the authentication, privilege, and native resource boundaries
described in the [security overview](../security.md):

| Path | Relevant implementation |
| --- | --- |
| [src/main.rs](../../src/main.rs) and [tests/service_entry.rs](../../tests/service_entry.rs) | Argument rejection, SCM-only BFD entry, and direct-launch regressions |
| [installer/Package.wxs](../../installer/Package.wxs) | Service accounts, dependencies, SCM control/query ACLs, Parameters ACL, and firewall rules |
| [src/service.rs](../../src/service.rs) and [src/bgp_broker/service.rs](../../src/bgp_broker/service.rs) | SCM lifecycle, startup identity checks, local RPC lifetime, and private broker COM initialization |
| [src/runtime/privileges.rs](../../src/runtime/privileges.rs) | Read-only validation of both SCM-issued privilege sets; token adjustment is confined to the test-only [fixture](../../src/runtime/privileges/fixture.rs) |
| [scripts/Test-ServicePrivilegePolicy.ps1](../../scripts/Test-ServicePrivilegePolicy.ps1) | Disposable-host checks for rejection of excessive SCM privileges and recovery after restoring the minimum |
| [src/bgp_broker/install.rs](../../src/bgp_broker/install.rs) | Transactional SCM policy, BFD dependency removal, and bounded dependency rollback snapshot |
| [src/transport.rs](../../src/transport.rs) | `Datagram::validate`, transport construction, `send`, and `send_reply` |
| [src/session.rs](../../src/session.rs), [src/packet.rs](../../src/packet.rs), and [src/seamless.rs](../../src/seamless.rs) | `receive_checked`, `receive_seamless`, `AuthConfig::verify_decoded`, and `respond_checked` |
| [src/local_rpc.rs](../../src/local_rpc.rs) and [src/local_rpc/monitor.rs](../../src/local_rpc/monitor.rs) | Private local RPC listener, in-process client, authentication, authorization, supervised worker, and telemetry cache |
| [src/local_rpc/identity.rs](../../src/local_rpc/identity.rs) | Per-call transport/authentication checks and bounded Authz identity queries without token attachment |
| [rpc/bfd_local.idl](../../rpc/bfd_local.idl), [rpc/client.c](../../rpc/client.c), and [rpc/server.c](../../rpc/server.c) | Status-only contract, fixed record, MIDL stub bridge, native asynchronous deadlines, and RPC exception boundary |
| [rpc/build.rs](../../rpc/build.rs) and [rpc/allocator.c](../../rpc/allocator.c) | Native MIDL/MSVC build flags, static library assembly, and RPC allocation hooks |
| [src/runtime/status.rs](../../src/runtime/status.rs), [src/local_rpc/status.rs](../../src/local_rpc/status.rs), and [src/runtime/state.rs](../../src/runtime/state.rs) | Immutable publications and checked RPC projection; the immediate atomic state observer stays separate from detailed telemetry |
| [src/bgp_broker/com.rs](../../src/bgp_broker/com.rs) | Private broker COM security for native MI |
| [src/bgp/ipc.rs](../../src/bgp/ipc.rs) | `require_broker_identity`, Authz authorization, bounded dispatch, and BGP RPC client/listener |
| [src/bgp.rs](../../src/bgp.rs) and [src/bgp_broker.rs](../../src/bgp_broker.rs) | Bounded BGP mailbox, state-to-action policy, fixed target, and request dispatch |
| [src/bgp_broker/mi.rs](../../src/bgp_broker/mi.rs) | Local MI destination, impersonation option, namespace, and provider calls |
| [src/config/registry.rs](../../src/config/registry.rs) and [src/config/dpapi.rs](../../src/config/dpapi.rs) | Validated registry loading, bounded DPAPI decryption, plaintext allocation cleanup, `SettingsWatch`, and `load_bgp_target` |
| [scripts/Set-BfdAuthenticationKey.ps1](../../scripts/Set-BfdAuthenticationKey.ps1) | Stopped-service key administration, protected ACL validation, machine-scope encryption, and read-back verification |
| [src/runtime/logging.rs](../../src/runtime/logging.rs) and [events/BFD-Service.man](../../events/BFD-Service.man) | Diagnostic queues, ETW output, optional file logging, and event channel |

# Local RPC security

Cowabunga, RPC crew. Follow the identity checks in both directions. Developers
and security reviewers, here's the local-RPC security lineup, dude. This
reference traces identity checks, authorization, and resource ownership for the
two private service Remote Procedure Call (RPC) channels. The call flows show
logical security gates. For the identity matrix and visual overview, see
[Local RPC authentication and authorization](../rpc-authentication.md). The
[status contract](../rpc-session-status-design.md) owns wire fields and telemetry policy.

See the [security overview](../security.md) for the full boundary map. On this
page:

- [BGP control server identity](#bfd-authenticates-the-broker)
- [BGP request authorization](#broker-authenticates-and-authorizes-bfd-requests)
- [Telemetry authentication](#broker-authenticates-bfd-telemetry)
- [Soundness and operational limits](#soundness-and-operational-limits)
- [Deadlines and recovery](#deadlines-and-recovery)
- [Concurrency and availability](#concurrency-and-availability)

## BFD authenticates the broker

Ninja discipline checks who actually owns the endpoint. BFD calls the broker's
`BgpControl` version `2.0` interface at the fixed `ncalrpc` endpoint
`BfdWinService.Bgp.v2`. It uses the same binding helper as the telemetry query,
with the server identities reversed: LocalSystem and the
`NT SERVICE\BfdBgpBroker` SID must both satisfy the V5 server security
descriptor. `QOS.Sid` also pins LocalSystem. An endpoint name alone never
establishes identity. A familiar name doesn't pass the identity vibe check.

Both clients request WINNT authentication with packet privacy, mutual
authentication, static identity tracking, identification level, and
effective-only credentials. Each binding is unique and uses
`RPC_BHO_DONTLINGER`. Each process keeps its expected server policy fixed. See
[binding and server setup](#binding-and-server-setup) for
the conditional ACE and Microsoft's security references.

## Broker authenticates and authorizes BFD requests

### Startup and registration

Get the broker identity ready before the turtle team accepts requests. The
broker checks LocalSystem in its own `TokenUser` and its enabled, non-deny-only
service SID before registering the interface. It secures the endpoint and
interface before reporting Running. Registration or endpoint collision fails
startup; there is no alternate endpoint or pipe fallback.

The endpoint and interface use a protected DACL admitting the BFD service SID.
The shared registration helper applies `RPC_IF_AUTOLISTEN`,
`RPC_IF_ALLOW_LOCAL_ONLY`, `RPC_IF_ALLOW_SECURE_ONLY`, and
`RPC_IF_SEC_NO_CACHE`, and denies runtime management operations. The callback
runs for every call and checks native locality, `RPC_PROTSEQ_LRPC`, WINNT
authentication, packet privacy, and a non-null session before application
arguments are unmarshaled.

### Caller authorization

Give every caller the Donatello treatment: inspect the authenticated identity.
The manager checks again, buddy: it repeats authorization and queries an Authz
context with `RpcGetAuthorizationContextForClient(ImpersonateOnReturn=FALSE)`,
requiring LocalService as the exact user and an enabled, non-deny-only BFD
service group. For a restricted caller, `AuthzContextInfoRestrictedSids` must
also contain the BFD service SID, including for write-restricted tokens.
Unrelated LocalService processes, ordinary administrator clients, and tokens
missing either required service-SID entry are rejected. Native information uses
the same bounded, aligned, pointer-validated storage as the telemetry query. The
context is released on both success and failure. Neither RPC server impersonates
callers or opens peer process tokens.

### Fixed operations and bounded dispatch

Keep the operation list tight before anyone gets to kick shell: the robust MIDL
contract admits only `Get`, `Start`, or `Stop`, with a fixed eight-byte result
containing 32-bit provider status and Boolean value fields. Each functional call
authenticates independently. There is no connection probe, broker-instance
tracking, custom byte frame, or application connection sequence. RPC supplies
authenticated message protection.
Neither RPC dispatch nor a transport disconnect independently requests a
provider mutation.

One provider request can wait in the bounded queue, and one control manager
holds the admission permit at a time. Provider calls execute serially on the
existing watched worker. Cancelled or expired queued requests are discarded.
Cancellation cannot undo an operation already executing in MI; its outcome can
be unknown to the caller. The controller reconciles its latest desired state
rather than interpreting a transport failure as BGP state.

### Protected BGP target

Turtle power stays within the configured target boundary. The broker
independently reads only the BGP peer name and routing domain from protected
Parameters at startup. Requests don't get to freestyle a peer, routing domain,
command, path, or registry key. The broker uses its own LocalSystem authority
only for that fixed target. This is the service's BGP action policy, not an
interactive administrator credential passed through the BFD process.

## Broker authenticates BFD telemetry

Cowabunga, telemetry crew. Follow the status call back to BFD. BFD hosts
`BfdWinService.Local.v2` on `ncalrpc`, interface version `2.0`. Its sole
operation, `GetSessionStatusV1`, returns a fixed session-status record and
verifies authenticated connectivity through the same call.

This boundary requires local transport, explicit service identities, read-only
telemetry, and bounded work. The security checks stay separate from the packet
engine and the broker's BGP action policy.

The broker uses a dedicated RPC worker and supervisor inside its existing
process. It creates no helper process or reply pipe and does not change its
provider token or COM/MI initialization. One BFD identity policy remains fixed
for the process lifetime; separate bindings are not treated as cache flushing.

The implementation is in [local RPC setup](../../src/local_rpc.rs) and [per-call
identity validation](../../src/local_rpc/identity.rs). The ASCII diagrams show
the logical security gates, rather than the RPC runtime's exact handshake or
callback scheduling.

### Binding and server setup

The mutual-authentication vibe check runs both ways. The broker specifies its
expected server identity; BFD separately registers the endpoint, application
interface, and management policy:

```text
BROKER CLIENT: one fixed BFD identity policy
  RpcBindingCreateW
    RPC_PROTSEQ_LRPC -> BfdWinService.Local.v2
    RPC_C_AUTHN_WINNT + RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    RPC_SECURITY_QOS_V5_W:
      MUTUAL_AUTH, STATIC, IDENTIFY, EffectiveOnly=1
      Sid=LocalService
      ServerSecurityDescriptor=LocalService AND BFD service SID
          |
          v
  RpcBindingSetOption(RPC_C_OPT_UNIQUE_BINDING, 1)
          |
          v
  Native RpcBindingBind, then GetSessionStatusV1
    server identity mismatch or API failure -> query fails; no status

BFD SERVER: verify its own restricted service token first
  RpcMgmtSetAuthorizationFn(deny_management)
    management request -> ERROR_ACCESS_DENIED
          |
          v
  RpcServerUseProtseqEpW("ncalrpc", endpoint, broker-SID ACL)
          |
          v
  RpcServerRegisterAuthInfoW(RPC_C_AUTHN_WINNT)
          |
          v
  RpcServerRegisterIf3(interface, flags, authorize, broker-SID ACL)
    setup failure -> fail startup; no fallback policy
          |
          v
  Windows interface ACL check -> security callback -> manager
    ACL denial -> reject before callback or manager
```

`RpcBindingCreateW` builds a fast binding; success alone establishes neither
connectivity nor server identity. The native wrapper subsequently calls
`RpcBindingBind`. The binding uses Windows credentials through a null
`AuthIdentity`; it supplies no application password. See Microsoft's
[RpcBindingCreateW
reference](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingcreatew).

The client sets `RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH`,
`RPC_C_QOS_IDENTITY_STATIC`, and `RPC_C_IMP_LEVEL_IDENTIFY` in
`RPC_SECURITY_QOS_V5_W`. Static tracking captures credentials for that binding;
Identify permits identity and ACL checks without allowing BFD to access
resources as the privileged broker. `EffectiveOnly=1` exposes enabled privileges
only; it is not the service-group authorization check. See Microsoft's [QOS V5
contract](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v5_w).

`QOS.Sid` identifies LocalService, while `ServerSecurityDescriptor` contains one
conditional allow ACE requiring both LocalService and the BFD service SID.
`Member_of` tests all listed enabled SIDs for an allow ACE; two independent
allow ACEs would instead permit either identity. The descriptor adds the
service-specific server check: the mutual-authentication capability flag alone
is insufficient because a provider can report that capability without
establishing the server's identity. See Microsoft's [conditional ACE
semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
and [QOS provider
caveat](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v5_w).

On BFD, `RpcMgmtSetAuthorizationFn` denies every runtime management operation
before the endpoint opens. This is separate from the application interface's ACL
and callback. `RpcServerUseProtseqEpW` registers only `ncalrpc` with an explicit
broker-SID endpoint ACL; `RpcServerRegisterAuthInfoW` registers WINNT without a
custom key callback. See Microsoft's [management
authorization](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcmgmtsetauthorizationfn),
[endpoint
registration](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserveruseprotseqepw),
and [authentication
registration](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterauthinfow).

`RpcServerRegisterIf3` also receives an explicit broker-SID interface ACL and
the authorization callback. Windows checks that ACL before invoking the
callback, including the access restrictions of the caller's token. The endpoint
ACL alone is insufficient. The interface uses these flags:

| Flag | Purpose and limit |
| --- | --- |
| `RPC_IF_ALLOW_LOCAL_ONLY` | Reject remote clients; the callback additionally requires LRPC and confirmed local origin. |
| `RPC_IF_ALLOW_SECURE_ONLY` | Reject unauthenticated calls; this flag alone does not require privacy, exclude null sessions, or prove a privileged caller. |
| `RPC_IF_SEC_NO_CACHE` | Run the security callback for each call; this does not disable every Windows identity or association cache. |
| `RPC_IF_AUTOLISTEN` | Give this interface an automatic listening lifetime without calling process-wide `RpcServerListen` or `RpcMgmtStopServerListening`. |

See Microsoft's [RpcServerRegisterIf3
ordering](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3)
and [interface flag
definitions](https://learn.microsoft.com/en-us/windows/win32/rpc/interface-registration-flags).

The descriptor uses this form:

```text
D:(XA;;GA;;;WD;(Member_of {SID(S-1-5-19), SID(BFD_SERVICE_SID)}))
```

`BFD_SERVICE_SID` represents the numeric SID in the
[service identity reference](service-isolation.md#numeric-service-sids). Rust
constructs this descriptor internally; it is not an administrator-configurable
setting. `Member_of` requires all listed enabled SIDs. Two separate allow ACEs
would permit either identity independently. `QOS.Sid` alone does not express the
required service-group policy. See Microsoft's
[conditional ACE semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-).

An endpoint name is an address, not identity evidence. A process occupying the
name cannot produce an accepted result without satisfying the server policy.
BFD startup treats an endpoint collision as an error rather than choosing a
different address or accepting another server's endpoint.

#### Fixed policy and RPC caches

The broker keeps its BFD account/service-SID policy immutable for the process
lifetime and uses no permissive/default policy for the BFD endpoint.
`RPC_C_OPT_UNIQUE_BINDING` separates a transport connection;
`RPC_BHO_DONTLINGER` avoids retaining it after release. Neither is treated as a
promise to clear authorization caches. Assuming otherwise would be bogus. See
[RPC binding options](https://learn.microsoft.com/en-us/windows/win32/rpc/binding-option-constants).

Native investigation observed cached decisions when changing the expected
policy for the same actual server token. That does not make a separate process
mandatory for fixed-policy calls. The in-process coexistence test runs real
read-only MI provider traffic alongside BFD RPC, rejects a replacement server
whose actual token lacks the required group, and verifies successful recovery.
The broker's existing COM/MI policy and token remain unchanged.

### Per-call authorization and cleanup

The interface callback and the application manager both call the same identity
guard. The manager repeats the guard before loading a status snapshot. That
second check enforces authorization at the point of use:

```text
Windows interface ACL passes
          |
          v
  RpcServerInqCallAttributesW(RPC_CALL_ATTRIBUTES_V2_W)
    require LRPC + rcclLocal + NullSession=0 + WINNT + privacy
    API failure or mismatch -------------------------> DENY
          |
          v
  RpcGetAuthorizationContextForClient(ImpersonateOnReturn=FALSE)
    API failure or null context ---------------------> DENY
          |
          v
  AuthzGetInformationFromContext
    AuthzContextInfoUserSid    -> TOKEN_USER
    AuthzContextInfoGroupsSids -> TOKEN_GROUPS
    AuthzContextInfoRestrictedSids -> TOKEN_GROUPS
          |
          v
  Validate native buffer lengths, group entries, and SID bounds
          |
          v
  EqualSid: user == SYSTEM
  EqualSid: group == broker service SID
    group enabled; not SE_GROUP_USE_FOR_DENY_ONLY
  Nonempty restricting list -> also require broker service SID
          |
          +-- query / bounds / identity failure --+
          |                                     |
          v                                     v
  RpcFreeAuthorizationContext        RpcFreeAuthorizationContext
          |                                     |
          v                                     v
        ALLOW                                  DENY

Callback allows -> manager repeats guard -> bounded snapshot copy
```

`RpcServerInqCallAttributesW` receives a version-2 structure with
`RPC_QUERY_IS_CLIENT_LOCAL`. The code requires `RPC_PROTSEQ_LRPC`, `rcclLocal`,
`NullSession == 0`, `RPC_C_AUTHN_WINNT`, and an authentication level at least
`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`. Unavailable or unexpected attributes deny the
call. See Microsoft's [call-attribute
query](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcserverinqcallattributesw)
and [version-2
fields](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/ns-rpcasync-rpc_call_attributes_v2_w).

`RpcGetAuthorizationContextForClient` uses `ImpersonateOnReturn=FALSE` and zero
or null reserved parameters. The Authz queries read the authenticated caller's
identity without leaving its token attached to the BFD thread. This path does
not call `RpcImpersonateClient` or require added `SeImpersonatePrivilege`. See
Microsoft's [authorization-context
contract](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcgetauthorizationcontextforclient).

`AuthzGetInformationFromContext` retrieves `AuthzContextInfoUserSid`,
`AuthzContextInfoGroupsSids`, and `AuthzContextInfoRestrictedSids`. `EqualSid`
compares the account with SYSTEM and the service group with
`NT SERVICE\BfdBgpBroker`; the group must have
`SE_GROUP_ENABLED` and lack `SE_GROUP_USE_FOR_DENY_ONLY`. A same-account process
without that group fails. A nonempty restricting list must also contain the
broker service SID. The same guard enforces the corresponding BFD SID for BGP
control callers. Empty restricting lists remain valid for authorized unrestricted
callers. This extra identity gate applies to write-restricted tokens even when
native read access would pass; it supplements Windows ACL checks. See the
[write-restriction semantics](service-isolation.md#installed-service-tokens) and
Microsoft's [Authz
query](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzgetinformationfromcontext),
[information
classes](https://learn.microsoft.com/en-us/windows/win32/api/authz/ne-authz-authz_context_information_class),
and [EqualSid
preconditions](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-equalsid).

The Rust wrapper bounds each identity result to 1 MiB, uses initialized aligned
storage, and checks structure lengths, group-count arithmetic, SID alignment,
revision, and SID body bounds before native comparison. An acquired context is
owned by a drop guard and released with `RpcFreeAuthorizationContext` on both
success and rejection, rather than `AuthzFreeContext`. See Microsoft's [RPC
context
release](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcfreeauthorizationcontext).

### Soundness and operational limits

Windows checks the expected server, the interface ACL gates callers, and the
callback and manager require the exact caller identity. BFD retains its reduced
identity throughout the exchange. These checks assume trustworthy Windows
authentication, SCM token construction, protected configuration/binaries, and
correct native RPC/Authz behavior. Administrators and SYSTEM remain trusted; a
matching SID does not attest which executable is running.

The status and availability boundaries apply these additional checks:

| Surface | Enforced policy and limit |
| --- | --- |
| Status record | Robust fixed-size MIDL stubs and one Rust conversion use enums, `TryFrom`, `NonZero`, checked time arithmetic, and canonical optional fields. Valid shape does not prove a report is truthful. |
| Invalid status | Discard the whole record, clear prior cached telemetry, retry with capped backoff, and rate-limit Error 301 to once per minute; provider work continues. |
| Native boundary | MIDL, the C exception bridge, Windows APIs, and unsafe Rust wrappers must uphold their layout, bounds, and lifetime contracts. Handwritten C passes MSVC static analysis; all native C uses `/W4 /WX`. The shared Windows RPC exception filter excludes documented fatal faults from recovery. Safe Rust validation cannot repair prior native memory corruption. |
| Authorized malicious source | A compromised authorized BFD process can return structurally valid false telemetry or withhold replies. Authentication establishes source identity, not session truth. |

### Deadlines and recovery

Bind and call cancellation retain their output, async state, events, binding,
SID, and descriptor allocations until native completion. A successful bind that
races with cancellation is unbound before returning failure. Timeout does not
prove that the server stopped executing. See the
[cancellation contract](../rpc-session-status-design.md#cancellation-and-shutdown)
for exact deadlines, supervision, quarantine, and shutdown behavior.

Completed query failures and rejected replies clear the cache and retry;
only an unfinished native worker causes quarantine. See the
[failure and retry policy](../rpc-session-status-design.md#secure-response-to-invalid-data).
Fatal native faults remain outside recoverable RPC exception handling.

### Concurrency and availability

`MaxRpcSize` does not constrain LRPC, and `MaxCalls` is best effort; a separate
nonblocking permit caps status managers at four. RPC workers read snapshots
without taking a lock on the packet engine. These bounds reduce contention but
do not guarantee availability under host resource exhaustion or an authorized
client's repeated requests. Status fetches, invalid replies, timeouts, and
quarantine never fabricate a BFD Down state or issue BGP actions. The existing
BGP control RPC interface and COM/MI provider policy remain separate.

Native tests cover malformed replies, identity rejection, cancellation, and
same-process coexistence with real read-only MI provider traffic. Installed
SCM-issued identities still require the separate MSI first-start/repair check.
For the identity matrix and diagram, see
[RPC authentication](../rpc-authentication.md). For payload bounds and failure
policy, see [RPC session-status query](../rpc-session-status-design.md). For
native exception handling and cross-language unwinding rules, see the
[native C exception policy](build-hardening.md#native-c-exception-policy).

## Runtime management operations

RPC runtime management is a separate interface. BFD installs a process-wide
`RpcMgmtSetAuthorizationFn` callback before opening its endpoint and denies
every management operation. This policy remains installed until process exit. It
does not change the broker provider host's COM/MI process security.

The runtime defaults and BFD's policy are:

| Operation | Windows default | BFD policy |
| --- | --- | --- |
| Enumerate interfaces | Allowed | Denied |
| Query server principal name | Allowed | Denied |
| Query runtime statistics | Allowed | Denied |
| Query listener state | Allowed | Denied |
| Stop the listener | Denied | Denied |

The status interface needs none of these operations. Its application-interface
ACL does not replace runtime-management authorization. See Microsoft's
[RPC management authorization defaults](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcmgmtsetauthorizationfn).

## Verify the implementation

Follow
[native RPC validation](../development/validation.md#verify-native-rpc-boundaries)
for the default suites and opt-in MI/RPC coexistence commands.

Expect zero failures. Ignored child-process entry points are invoked explicitly
by their parent tests. The MI/RPC coexistence and installed-service checks are
opt-in; use the opt-in commands in the validation guide.
Native restricted-token fixtures require a normal Windows token environment;
an already-restricted sandbox can prevent `CreateRestrictedToken` from
constructing those fixtures.

The fixtures use the test account and existing groups. They verify account and
group rejection in fresh clients, same-account server replacement at the same
endpoint, anonymous callers, runtime management denial, native cancellation,
Rust conversion, rejected-data recovery, stalled-worker quarantine, and bounded
shutdown. They do not impersonate an installed service. The explicit coexistence test also
checks fixed-policy RPC against real read-only MI provider traffic.

The release workflow's `Test-MsiInstall.ps1` separately requires a fresh broker
event confirming an authenticated status query after first start and after repair. After first
start, broker recovery, and repair, it also uses the authenticated administrator
runner's own credentials to require access denied from the BFD status operation
and all three broker control operations. These checks call the native RPC helpers
directly, bypassing client-side service-identity guards so the receiving RPC
interfaces must enforce rejection. The disposable-runner test exercises the
actual SCM-issued service accounts, service SIDs, and restricted BFD token.
Fixture success does not establish that installed
validation passed. For operational queries, see
[Verify broker-to-BFD authentication](../monitoring.md#verify-broker-to-bfd-authentication).

## Source map

For the code deep dive, follow this file lineup:

| File | Responsibility |
| --- | --- |
| [src/local_rpc.rs](../../src/local_rpc.rs) | Registration, management denial, fixed client policy, snapshot manager, and binding ownership |
| [src/local_rpc/status.rs](../../src/local_rpc/status.rs) | Fixed record, checked Rust conversion, and typed session observation |
| [src/local_rpc/identity.rs](../../src/local_rpc/identity.rs) | Call attributes, Authz context ownership, and account/group checks |
| [src/local_rpc/monitor.rs](../../src/local_rpc/monitor.rs) | In-process worker supervision, typed status cache, quarantine, and bounded shutdown |
| [src/service_identity.rs](../../src/service_identity.rs) | Self-identity and restricted BFD token checks |
| [src/runtime/privileges.rs](../../src/runtime/privileges.rs) | Read-only BFD and broker privilege validation before accepting work |
| [rpc/bfd_local.idl](../../rpc/bfd_local.idl) and [client ACF](../../rpc/bfd_local_client.acf) | Status-only contract, fixed field ranges, and asynchronous client generation |
| [rpc/client.c](../../rpc/client.c), [server bridge](../../rpc/server.c), and [RPC build](../../rpc/build.rs) | Native completion, cancellation, exceptions, manager bridge, and MIDL compilation |
| [RPC tests](../../src/local_rpc/tests.rs) and [replacement-token tests](../../src/local_rpc/tests/restricted.rs) | Native positive and negative fixtures |
| [MSI installation tests](../../scripts/Test-MsiInstall.ps1) | Actual service status queries and rejection of unrelated authenticated RPC callers after install, recovery, and repair |

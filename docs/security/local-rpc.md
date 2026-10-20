# Local RPC security

For developers and security reviewers, this reference traces identity checks,
authorization, and resource ownership for the two private service Remote
Procedure Call (RPC) channels. The call flows show logical security gates. For
the API contract and Microsoft guidance, see [Local RPC authentication and
authorization](../rpc-authentication.md).

See the [security overview](../security.md) for the full boundary map. On this
page:

- [BGP control server identity](#bfd-authenticates-the-broker)
- [BGP request authorization](#broker-authenticates-and-authorizes-bfd-requests)
- [Telemetry authentication](#broker-authenticates-bfd-telemetry)
- [Soundness and operational limits](#soundness-and-operational-limits)
- [Deadlines and recovery](#deadlines-and-recovery)
- [Concurrency and availability](#concurrency-and-availability)

## BFD authenticates the broker

BFD calls the broker's `BgpControl` version `1.0` interface at the fixed
`ncalrpc` endpoint `BfdWinService.Bgp.v1`. It uses the same binding helper as
the telemetry query, with the server identities reversed: LocalSystem and the
`NT SERVICE\BfdBgpBroker` SID must both satisfy the V5 server security
descriptor. `QOS.Sid` also pins LocalSystem. An endpoint name alone never
establishes identity.

Both clients request WINNT authentication with packet privacy, mutual
authentication, static identity tracking, identification level, and
effective-only credentials. Each binding is unique and uses
`RPC_BHO_DONTLINGER`. Each process keeps its expected server policy fixed. See
[server identity checks](../rpc-authentication.md#server-identity-checks) for
the conditional ACE and Microsoft's security references.

## Broker authenticates and authorizes BFD requests

### Startup and registration

The broker checks LocalSystem in its own `TokenUser` and its enabled,
non-deny-only service SID before registering the interface. It secures the
endpoint and interface before reporting Running. Registration or endpoint
collision fails startup; there is no alternate endpoint or pipe fallback.

The endpoint and interface use a protected DACL admitting the BFD service SID.
The shared registration helper applies `RPC_IF_AUTOLISTEN`,
`RPC_IF_ALLOW_LOCAL_ONLY`, `RPC_IF_ALLOW_SECURE_ONLY`, and
`RPC_IF_SEC_NO_CACHE`, and denies runtime management operations. The callback
runs for every call and checks native locality, `RPC_PROTSEQ_LRPC`, WINNT
authentication, packet privacy, and a non-null session before application
arguments are unmarshaled.

### Caller authorization

The manager repeats authorization. It queries an Authz context with
`RpcGetAuthorizationContextForClient(ImpersonateOnReturn=FALSE)`, requiring
LocalService as the exact user and an enabled, non-deny-only BFD service group.
For a restricted caller, `AuthzContextInfoRestrictedSids` must also contain the
BFD service SID, including for write-restricted tokens. Unrelated LocalService
processes, ordinary administrator clients, and tokens missing either required
service-SID entry are rejected. Native information uses the same bounded,
aligned, pointer-validated storage as the telemetry query. The context is
released on both success and failure. Neither RPC server impersonates callers
or opens peer process tokens.

### Fixed operations and bounded dispatch

The robust MIDL contract admits only a liveness probe and `Get`, `Start`, or
`Stop`, with a fixed 16-byte result containing a broker-instance nonce, provider
status, and a Boolean value. The nonce detects restarts; it is not
authentication evidence. There is no custom byte frame or application connection
sequence. RPC supplies authenticated message protection. Neither RPC dispatch
nor a transport disconnect independently requests a provider mutation.

One provider request can wait in the bounded queue, and one control manager
holds the admission permit at a time. Provider calls execute serially on the
existing watched worker. Cancelled or expired queued requests are discarded.
Cancellation cannot undo an operation already executing in MI; its outcome can
be unknown to the caller. The controller reconciles its latest desired state
rather than interpreting a transport failure as BGP state.

### Protected BGP target

The broker independently reads only the BGP peer name and routing domain from
protected Parameters at startup. Requests cannot specify a peer, routing domain,
command, path, or registry key. The broker uses its own LocalSystem authority
only for that fixed target. This is the service's BGP action policy, not an
interactive administrator credential passed through the BFD process.

## Broker authenticates BFD telemetry

BFD hosts `BfdWinService.Local.v2` on `ncalrpc`, interface version `2.0`.
Its sole operation, `GetSessionStatusV1`, returns a fixed session-status record
and verifies authenticated connectivity through the same call.

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

Setup checks identities in both directions. The broker specifies its expected
server identity; BFD separately registers the endpoint, application interface,
and management policy:

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
          |
          v
  Validate native buffer lengths, group entries, and SID bounds
          |
          v
  EqualSid: user == SYSTEM
  EqualSid: group == broker service SID
    group enabled; not SE_GROUP_USE_FOR_DENY_ONLY
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

`AuthzGetInformationFromContext` retrieves `AuthzContextInfoUserSid` and
`AuthzContextInfoGroupsSids`. `EqualSid` compares the account with SYSTEM and
the service group with `NT SERVICE\BfdBgpBroker`; the group must have
`SE_GROUP_ENABLED` and lack `SE_GROUP_USE_FOR_DENY_ONLY`. A same-account process
without that group fails. These explicit identity comparisons supplement the
runtime ACL check; they do not reimplement restricted-token access checking. See
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

### Authz responsibilities

The implemented Authz path fits the requirement to compare the exact account SID
and enabled service SID directly. Rejection tests cover that policy. The Authz
wrapper owns native buffer parsing, context lifetime, and cleanup. The
authorization policy, transport/authentication checks, correct API use, and
reviewed FFI boundary determine whether the implementation enforces its intended
trust boundary.

### Soundness and operational limits

The layered design is sound for the stated local-service identity boundary, and
the recorded regression tests support that assessment. Windows checks the
expected server, the interface ACL gates callers, the callback and manager
require the exact broker identity, and BFD never adopts the broker's token for
resource access. The network-facing process keeps its reduced identity
throughout the exchange. This is a design assessment, not a proof of Rust memory
soundness or the absence of vulnerabilities. It assumes trustworthy Windows
authentication, SCM service-token construction, protected configuration and
binaries, and the native RPC/Authz implementation. Administrators and SYSTEM
that can replace code or change service policy remain trusted; a matching SID
does not attest which executable is running.

The status and availability boundaries apply these additional checks:

| Surface | Enforced policy and limit |
| --- | --- |
| Status record | Robust fixed-size MIDL stubs and one Rust conversion use enums, `TryFrom`, `NonZero`, checked time arithmetic, and canonical optional fields. Valid shape does not prove a report is truthful. |
| Invalid status | Discard the whole record, clear prior cached telemetry, retry with capped backoff, and rate-limit Error 301 to once per minute; provider work continues. |
| Native boundary | MIDL, the C exception bridge, Windows APIs, and unsafe Rust wrappers must uphold their layout, bounds, and lifetime contracts. Handwritten C passes MSVC static analysis; all native C uses `/W4 /WX`. The shared Windows RPC exception filter excludes documented fatal faults from recovery. Safe Rust validation cannot repair prior native memory corruption. |
| Authorized malicious source | A compromised authorized BFD process can return structurally valid false telemetry or withhold replies. Authentication establishes source identity, not session truth. |

### Deadlines and recovery

Native bind and call deadlines are two seconds each. An eight-second supervisor
budget quarantines a stuck worker. Its owned native storage remains live;
shutdown does not kill that thread, free pending buffers, or wait indefinitely
for it. At most one monitored RPC operation can remain unfinished.

Completed failures back off through 1, 2, 4, 8, 16, then 30 seconds. A valid
reply resets polling to one second, and Stop interrupts the wait. Rejecting a
field does not establish memory corruption or require quarantine. Fatal native
faults are not converted to recoverable RPC errors. Authentication prevents
unrelated processes from injecting replies; checked conversion handles incorrect
values from an authenticated source. See [injection and Rust's safety
boundary](../rpc-session-status-design.md#injection-and-rusts-safety-boundary).

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
For API settings and primary references, see [RPC
authentication](../rpc-authentication.md). For payload bounds and failure
policy, see [RPC session-status query](../rpc-session-status-design.md). For
native exception handling and cross-language unwinding rules, see the [native C
exception policy](build-hardening.md#native-c-exception-policy).

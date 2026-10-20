# Local RPC authentication and authorization

For developers and Windows administrators, this reference explains how Windows
Remote Procedure Call (RPC) authenticates the BGP broker and BFD service, which
Windows rights they use, and how the implementation follows Microsoft's
security guidance. For the complete process topology, see
[Service communication](service-communication.md).

Both private service interfaces use `ncalrpc`. Windows names this transport
LRPC in native constants such as `RPC_PROTSEQ_LRPC`; the label does not identify
a different security mode. Both bindings require WINNT packet privacy and the
same service-specific authentication and authorization helpers.

Call initiation is directional: the broker calls BFD for `Probe` and session
status; BFD calls the broker for BGP control. Replies return on the respective
calls. Neither IDL declares RPC callbacks, and the fast bindings reject
server-initiated callbacks. The local security callbacks authorize incoming
calls without contacting the caller. See [fast-binding restrictions](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingbind).

The endpoint name isn't the identity check. The receipts are the authenticated
account and enabled service SID on each side.

The implemented interface provides a connection probe and a bounded read-only
session-status operation. Status data returns directly to a worker inside the
broker process over packet-private RPC. It carries no configuration commands,
authentication keys, or JSON records. The separate BGP control RPC interface and Windows
provider Component Object Model (COM) and Management Infrastructure (MI) API
keep their separate contracts. See [RPC session-status query](rpc-session-status-design.md)
for fields, accepted ranges, freshness, and telemetry quarantine.

## Find an RPC topic

Use these sections for a specific check or lifecycle question:

- [BGP control over local RPC](#bgp-control-over-local-rpc)
- [Interface and process boundaries](#interface-and-process-boundaries)
- [Accounts, service SIDs, and privileges](#accounts-service-sids-and-privileges)
- [Startup and query sequence](#startup-and-query-sequence)
- [Server identity checks](#server-identity-checks)
- [Caller identity and authorization](#caller-identity-and-authorization)
- [Runtime management operations](#runtime-management-operations)
- [Deadlines, cancellation, and resource ownership](#deadlines-cancellation-and-resource-ownership)
- [Wire validation and extension limits](#wire-validation-and-extension-limits)
- [Security best practices](#alignment-with-security-best-practices),
  [verification](#verify-the-implementation), and the [source map](#source-map)

## BGP control over local RPC

BFD also calls the broker over `ncalrpc`, using `BgpControl` version `1.0` at
`BfdWinService.Bgp.v1`. This replaces the BGP named-pipe transport. The two
channels share native binding, registration, call-attribute, and Authz helpers.
Deploy matching BFD and broker binaries together for this contract.

The identity requirements are:

| Gate | Broker querying BFD telemetry | BFD controlling BGP |
| --- | --- | --- |
| Expected server | LocalService and BFD service SID | LocalSystem and broker service SID |
| Interface DACL | Broker service SID | BFD service SID |
| Exact caller user | LocalSystem | LocalService |
| Enabled, non-deny-only caller group | Broker service SID | BFD service SID |
| Restricted caller check | Native interface ACL semantics | Also require BFD SID in any nonempty restricting list |

Both use WINNT packet privacy, QOS V5 with the conditional server descriptor,
static identity tracking, Identify, effective-only credentials, unique bindings,
and `DONTLINGER`. Both servers use local-only, secure-only, no-cache callbacks
and repeat authorization in their managers without impersonation. Management
operations are denied in both host processes; AUTOLISTEN preserves the broker's
COM listen lifecycle. The broker secures its control interface before reporting
Running, then starts its telemetry monitor without waiting for BFD startup.

The BGP contract has a probe and fixed Get/Start/Stop operations; callers cannot
supply targets. Robust MIDL range checks and Rust validation check a fixed
16-byte result record. One admission permit and a one-slot queue feed the existing serialized
provider worker. The client uses a two-second bind limit within a 30-second call
budget, or 20 seconds per final shutdown call. Probe calls use two seconds.
Cancellation drains native ownership; queued cancelled requests are discarded.
A provider operation already running can complete after cancellation. BFD aborts
if native ownership remains uncertain, while telemetry retains its existing
single-worker quarantine behavior. See [BGP recovery and cleanup](bgp.md#worker-retries-and-broker-recovery).

The remaining sections describe the telemetry direction in detail; the shared
security settings also apply to BGP control with the identities in this table.

## Interface and process boundaries

The RPC contract has these properties:

| Property | Implemented value |
| --- | --- |
| Server | `BfdWinService`, running `bfd-winservice.exe` |
| Authorized client | A dedicated worker inside the existing `BfdBgpBroker` process |
| Transport | Windows local RPC, `ncalrpc`; no TCP or RPC named-pipe transport |
| Endpoint | `BfdWinService.Local.v1`, supplied explicitly without endpoint-mapper registration |
| Interface | `BfdLocal`, UUID `8d10db9d-8aa1-4bd2-bcb6-0bc2e5597319`, version `1.1` |
| Operations | Parameterless `Probe` and `GetSessionStatusV1` with a fixed status output; binding is runtime context |
| Success | Native status `0`, after both identities pass their checks |
| Meaning | Authentication and the requested operation succeeded; status freshness and session state require separate interpretation |

The [editable draw.io source](service-communication.drawio) contains runtime,
lifecycle, and authentication pages. The authentication page shows the checks
performed by the client, Windows RPC, and server:

![RPC authentication call flow: RpcBindingCreateW uses Identify credentials and a BFD server descriptor. RpcServerRegisterIf3 applies the interface ACL before RpcServerInqCallAttributesW and RpcGetAuthorizationContextForClient(FALSE). AuthzGetInformationFromContext and EqualSid check SYSTEM plus the enabled broker SID; RpcFreeAuthorizationContext releases each acquired context.](images/service-communication-authentication.png)

For the matching ASCII diagrams, API responsibilities, and security assessment, see
[private local RPC authentication](security/local-rpc.md#broker-authenticates-bfd-telemetry).

The Windows RPC column represents runtime and kernel checks, not an additional
service process. Windows obtains identities from native tokens. The protocol
does not accept caller-supplied SIDs, process IDs, roles, passwords, or identity
metadata as authentication evidence.

## Accounts, service SIDs, and privileges

An account identifies a Windows logon identity. A service security identifier
(SID) distinguishes services that share an account. The Windows Service Control
Manager (SCM) applies the installed account, service SID type, and privilege
policy when it creates each service token. Both account and service identity
are required here:

| Process | Account in `TokenUser` | Enabled service group | Privilege policy |
| --- | --- | --- | --- |
| BFD service | LocalService, `S-1-5-19` | `NT SERVICE\BfdWinService` | SCM allowlist and startup removal retain `SeChangeNotifyPrivilege` and `SeCreateGlobalPrivilege` |
| Broker provider host | LocalSystem, `S-1-5-18` | `NT SERVICE\BfdBgpBroker` | Existing BGP provider privileges and COM/MI security remain in place |

The RPC identity checks require no added token privilege. The broker retains
its existing provider token rather than removing privileges process-wide.
Static Identify credentials restrict what BFD can do with the caller identity;
neither side enables debugging or impersonation privileges for this channel.
BFD separately retains its existing two-entry service privilege policy.

The numeric service SIDs are fixed by the Windows service names:

| Service | SID |
| --- | --- |
| `BfdWinService` | `S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512` |
| `BfdBgpBroker` | `S-1-5-80-3301813337-1731295767-1225795713-3993009034-49020719` |

BFD uses restricted service SID type `3`; the broker uses unrestricted type `1`.
Before opening configured resources, BFD verifies its LocalService account,
enabled non-deny-only service group, and the BFD SID plus write-restricted marker
`S-1-5-33` in `TokenRestrictedSids`. Windows applies the installed write
restriction to object access. The identity check does not replace those ACL
checks or treat the restricted token as a complete sandbox. See
[service identities and write restrictions](security/service-isolation.md#identities-and-privileges)
and Microsoft's [service SID types](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).

An unrelated LocalService process lacks BFD's service SID. An unrelated SYSTEM
process lacks the broker service SID. Administrator membership grants service
administration through SCM, but does not satisfy either RPC service identity.
Administrators who can replace installed executables or change SCM policy remain
part of the trusted host administration boundary.

## Startup and query sequence

Startup and status fetching follow this order:

1. SCM starts the broker dependency. The broker verifies SYSTEM and its service
   SID, initializes the COM/MI host, secures its BGP control RPC interface, and
   reports Running.
2. The broker starts the supervisor and one RPC worker inside its process. Startup
   does not wait for BFD, avoiding an SCM dependency cycle.
3. BFD verifies its restricted identity, removes unused privileges, creates its
   configured engine, and gives RPC a read-only snapshot observer. It denies runtime
   management and registers the interface before reporting Running.
4. The broker worker verifies its account/service SID and uses the fixed BFD
   identity descriptor for an asynchronous native fast binding. It initializes
   no additional COM security and creates no helper process or reply pipe.
5. Windows evaluates the server policy. BFD's ACL, callback, and manager require
   the authenticated local call and exact caller account/service SID.
6. The status manager loads one immutable snapshot under a nonblocking permit,
   copies the fixed record, and releases it. Packet processing receives no query.
7. Generated stubs check native bounds. Rust converts the record once into
   checked domain types before the supervisor publishes its cache.
8. The client completes and releases its native resources. The monitor reports
   connection/recovery, discards failed or invalid replies, and retries with
   backoff without a BGP action.

Successful queries repeat after one second. Consecutive failures back off through
1, 2, 4, 8, 16, then 30 seconds. A valid reply resets the delay. Ordinary failure
and rejected-data reports are each limited to one per minute, independently of
successful replies. Only an eight-second worker stall stops further fetches
until broker restart and logs one quarantine error. These monitoring events do
not replace BFD session-state events.

## Server identity checks

The client uses `RpcBindingCreateW` with an explicit local endpoint and the
following authentication and quality-of-service (QOS) settings:

| Setting | Value and purpose |
| --- | --- |
| Authentication service | `RPC_C_AUTHN_WINNT`, supported for local RPC |
| Authentication level | `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` |
| QOS version | `RPC_SECURITY_QOS_V5_W`, version `5` |
| Capabilities | `RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH` |
| Identity tracking | `RPC_C_QOS_IDENTITY_STATIC`, one fixed BFD client identity policy |
| Impersonation | `RPC_C_IMP_LEVEL_IDENTIFY`, enough for identity and ACL checks |
| Effective-only | `TRUE`, exposing enabled privileges only |
| Expected account SID | LocalService in `QOS.Sid` |
| Expected server descriptor | One conditional ACE requiring LocalService and the BFD service SID |
| Authentication identity | Null; Windows uses the broker worker's credentials |

The mutual-authentication flag alone is insufficient: Microsoft documents that
NTLM can report mutual-authentication negotiation without establishing the
server identity. The V5 server descriptor supplies the service-specific check.
See [RPC security QOS V5](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v5_w).

The descriptor uses this form:

```text
D:(XA;;GA;;;WD;(Member_of {SID(S-1-5-19), SID(BFD_SERVICE_SID)}))
```

`BFD_SERVICE_SID` represents the numeric BFD SID in the service-SID table. Rust
constructs this descriptor internally; it is not an administrator-configurable
setting. `Member_of` requires all listed enabled SIDs. Two separate allow ACEs
would permit either identity independently. `QOS.Sid` alone does not express the
required service-group policy. See Microsoft's
[conditional ACE semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-).

An endpoint name is an address, not identity evidence. A process occupying the
name cannot produce an accepted result without satisfying the server policy.
BFD startup treats an endpoint collision as an error rather than choosing a
different address or accepting another server's endpoint.

### Fixed policy and RPC caches

The broker keeps its BFD account/service-SID policy immutable for the process
lifetime and uses no permissive/default policy for the BFD endpoint.
`RPC_C_OPT_UNIQUE_BINDING` separates a transport connection;
`RPC_BHO_DONTLINGER` avoids retaining it after release. Neither is treated as a
promise to clear authorization caches. See
[RPC binding options](https://learn.microsoft.com/en-us/windows/win32/rpc/binding-option-constants).

Native investigation observed cached decisions when changing the expected
policy for the same actual server token. That does not make a separate process
mandatory for fixed-policy calls. The in-process coexistence test runs real
read-only MI provider traffic alongside BFD RPC, rejects a replacement server
whose actual token lacks the required group, and verifies successful recovery.
The broker's existing COM/MI policy and token remain unchanged.

## Caller identity and authorization

The endpoint and application interface use a protected discretionary access
control list (DACL) admitting the broker service SID. The server supplies the
descriptor explicitly rather than relying on the process token's default
descriptor. The interface ACL and callback are
separate gates: Windows checks the interface descriptor before the callback.
See [RPC interface security descriptors](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3).

The interface registration combines these flags:

| Flag | Purpose and limit |
| --- | --- |
| `RPC_IF_AUTOLISTEN` | Registration starts this interface; unregistering drains it without a process-wide listen/stop API |
| `RPC_IF_ALLOW_LOCAL_ONLY` | Rejects remote clients; the callback also requires the actual `ncalrpc` protocol |
| `RPC_IF_ALLOW_SECURE_ONLY` | Requires authenticated calls; it does not prove privilege, service membership, or a non-null session |
| `RPC_IF_SEC_NO_CACHE` | Runs the application security callback for every call |

The callback independently rejects the call unless all these attributes hold:

- The actual protocol is `RPC_PROTSEQ_LRPC` and locality is `rcclLocal`.
- The call uses WINNT authentication with packet privacy.
- `NullSession` is false.

Local-only flags alone can also admit some local named-pipe calls; secure-only
flags alone do not establish authorization. These explicit checks address both
limits. See [interface registration flags](https://learn.microsoft.com/en-us/windows/win32/rpc/interface-registration-flags)
and [native call attributes](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/ns-rpcasync-rpc_call_attributes_v2_w).

After checking the call, BFD obtains its native Windows authorization (Authz)
context:

1. Call `RpcGetAuthorizationContextForClient` with
   `ImpersonateOnReturn = FALSE` and all reserved arguments zero.
2. Query the Authz user and group information in initialized, aligned storage.
   Reject information larger than 1 MiB or with invalid counts, pointers, or SID
   boundaries before comparing identities.
3. Require `TokenUser` to match LocalSystem exactly and the broker service group
   to be enabled and not deny-only. Neither check substitutes for the other.
4. Release the context with `RpcFreeAuthorizationContext`, including on errors.

The server never calls `RpcImpersonateClient`, opens the peer process, or
enables `SeImpersonatePrivilege` or `SeDebugPrivilege` for these checks. BFD
continues executing under LocalService. Each manager repeats authorization
before returning `0`. Microsoft recommends a security callback for checking
credentials before application arguments are unmarshaled; see
[authenticated RPC servers](https://learn.microsoft.com/en-us/windows/win32/rpc/writing-an-authenticated-sspi-server)
and [RPC authorization contexts](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcgetauthorizationcontextforclient).

## Runtime management operations

RPC runtime management is a separate interface. BFD installs a process-wide
`RpcMgmtSetAuthorizationFn` callback before opening its endpoint and denies
every management operation. This policy remains installed until process exit.
It does not change the broker provider host's COM/MI process security.

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

## Deadlines, cancellation, and resource ownership

MIDL generates an asynchronous client stub with a synchronous server manager.
Binding and the status call each have a two-second deadline. The broker
supervisor applies an eight-second monitoring budget. `RPC_C_OPT_CALL_TIMEOUT`
is ignored for LRPC and is not used as that deadline. See
[call-timeout limitations](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetoption)
and [asynchronous binding](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingbind).

On timeout, the client requests abortive cancellation and waits for native
completion before completing the call and releasing storage. Output, async
state/event, binding, SID, and descriptor allocations remain owned throughout.
If a timed-out bind completes successfully during cancellation, C unbinds it
before returning failure. A timeout does not prove the server stopped executing.
See [RPC cancellation requirements](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcasynccancelcall).

The client unbinds before freeing a bound handle and releases its security
allocations afterward. If ownership becomes uncertain, that one worker retains
its stack and allocations. The supervisor quarantines telemetry rather than
aborting the provider host or launching replacement workers. Shutdown joins the
responsive supervisor and detaches an unfinished worker with its storage still
owned. No unsafe thread termination or early buffer release occurs. The C wrapper
converts recoverable RPC exceptions into errors with `RpcExceptionFilter`;
fatal native faults continue outside that handler. See
[unbind requirements](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingunbind)
and [binding lifetime requirements](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingfree).

BFD unregisters and drains only its own auto-listen interface before releasing
the descriptor. Endpoint and management policy stay process-scoped. This cleanup
does not register or stop the broker provider's COM interfaces.

## Wire validation and extension limits

MIDL generates `/robust` stubs for a fixed 336-byte x64 native status record.
It uses integer fields and fixed address/instance arrays, with no strings,
dynamic sizes, application pointers, selected BGP targets, or secret material.
Declared ranges protect native unmarshaling. A single Rust `TryFrom` conversion
constructs enums, nonzero identifiers, optional values, addresses, and checked
time values. There is no validation dependency or repeated validation pass.

Malformed replies clear cached telemetry to `Unavailable` and retry with capped
backoff on the same worker. The record is neither clamped nor partially accepted.
The broker stays Running and performs no BGP action because of rejected data.
Quarantine is reserved for a stuck native worker, not a cleanly rejected field.
The C wrapper uses `RpcExceptionFilter` and does not turn fatal native faults
into recoverable query errors. See
[accepted ranges and failure policy](rpc-session-status-design.md#native-and-rust-bounds).

`MaxRpcSize` is ignored for `ncalrpc`; the fixed contract supplies the size bound.
`MaxCalls = 8` is best effort, not a strict quota. Four nonblocking application
permits cap status manager work, and one supervised broker call can be in flight.
Further operations require their own bounds and authorization. See
[robust MIDL validation](https://learn.microsoft.com/en-us/windows/win32/midl/-robust),
[range checks](https://learn.microsoft.com/en-us/windows/win32/midl/range), and
[interface limits](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3).

## Alignment with security best practices

The implementation applies these principles:

| Principle | Implementation and evidence |
| --- | --- |
| Minimize exposed transports | Register only an explicit local endpoint; verify actual local RPC attributes. No RPC TCP listener or endpoint-mapper publication. |
| Separate authentication from authorization | Use Windows credentials for identity, then enforce the service SID and exact client account in addition to interface ACLs. |
| Authenticate the server | Pin LocalService and the BFD service SID through the V5 descriptor; do not rely on the endpoint name or mutual-authentication flag alone. |
| Use the least authority needed | Supply static Identify/effective-only credentials and query Authz without a caller thread token or added privileges. |
| Check each call | Disable callback caching and repeat the identity policy in the manager. |
| Keep service identity policy fixed | Use one BFD-specific expected policy and test replacement rejection alongside provider traffic in the same process. |
| Close alternate interfaces | Deny all runtime management operations independently of application authorization. |
| Bound waits and preserve ownership | Combine asynchronous deadlines, completion before release, and supervision of one owned worker. |
| Validate the wire contract | Use fixed robust stubs and one checked Rust conversion; discard malformed telemetry and retry with bounded backoff. |
| Test rejection and recovery | Exercise anonymous clients, wrong account/group identities, replacement servers, management denial, cancellation, and successful calls afterward. |

These are implementation controls and test results, not a claim that the service
contains a compromised host administrator or that an authenticated probe proves
protocol health.

## Verify the implementation

From the repository root on the supported Windows build host, run the RPC tests:

```powershell
cargo test-release --lib local_rpc::
```

Expect zero failures. Two ignored fixture tests are child-process entry points
that the parent tests invoke explicitly. The separate MI/RPC coexistence test
is opt-in; run it with the command in
[the status verification reference](rpc-session-status-design.md#verification-and-source-map).
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
event confirming the handshake after first start and after repair. That
disposable-runner test exercises the actual SCM-issued service accounts, service
SIDs, and restricted BFD token. Fixture success does not establish that installed
validation passed. For operational queries, see
[Verify broker-to-BFD authentication](monitoring.md#verify-broker-to-bfd-authentication).

## Source map

The implementation is divided across these files:

| File | Responsibility |
| --- | --- |
| [src/local_rpc.rs](../src/local_rpc.rs) | Registration, management denial, fixed client policy, snapshot manager, and binding ownership |
| [src/local_rpc/status.rs](../src/local_rpc/status.rs) | Fixed record, checked Rust conversion, and typed session observation |
| [src/local_rpc/identity.rs](../src/local_rpc/identity.rs) | Call attributes, Authz context ownership, and account/group checks |
| [src/local_rpc/monitor.rs](../src/local_rpc/monitor.rs) | In-process worker supervision, typed status cache, quarantine, and bounded shutdown |
| [src/service_identity.rs](../src/service_identity.rs) | Self-identity and restricted BFD token checks |
| [src/runtime/privileges.rs](../src/runtime/privileges.rs) | Permanent BFD privilege removal; the broker retains its provider token |
| [rpc/bfd_local.idl](../rpc/bfd_local.idl) and [client ACF](../rpc/bfd_local_client.acf) | Probe/status contract, fixed field ranges, and asynchronous client generation |
| [rpc/client.c](../rpc/client.c), [server bridge](../rpc/server.c), and [RPC build](../rpc/build.rs) | Native completion, cancellation, exceptions, manager bridge, and MIDL compilation |
| [RPC tests](../src/local_rpc/tests.rs) and [replacement-token tests](../src/local_rpc/tests/restricted.rs) | Native positive and negative fixtures |
| [MSI installation tests](../scripts/Test-MsiInstall.ps1) | Actual installed-service handshake after start and repair |

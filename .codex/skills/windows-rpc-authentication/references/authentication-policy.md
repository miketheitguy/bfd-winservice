# Exact local RPC policy

This policy is intentionally for Windows local private service RPC. Keep expected service identities fixed within a process. Values representing account/service SIDs are trusted policy inputs resolved from the intended installed roles, never supplied by an RPC caller.

## Client binding and server authentication

Create a fast binding with `RpcBindingCreateW` and retain all referenced policy storage for its full lifetime:

| Structure/setting | Required value |
| --- | --- |
| Binding template version | `1` |
| Protocol | `RPC_PROTSEQ_LRPC` for explicit `ncalrpc` |
| Endpoint | Explicit fixed endpoint; no fallback or endpoint-mapper publication |
| Binding security version | `1` |
| Authentication service | `RPC_C_AUTHN_WINNT` |
| Authentication level | `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` |
| Authentication identity | `NULL`, using the service's own fixed identity |
| QOS version | `5` |
| Capabilities | `RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH` |
| Identity tracking | `RPC_C_QOS_IDENTITY_STATIC` |
| Impersonation type | `RPC_C_IMP_LEVEL_IDENTIFY` |
| `Sid` | Expected server **account** SID |
| `EffectiveOnly` | `TRUE` |
| `ServerSecurityDescriptor` | Conditional descriptor requiring expected account and service SID together |
| Binding options flag | `RPC_BHO_DONTLINGER` |
| `RPC_C_OPT_UNIQUE_BINDING` | `1` |

Build the conditional descriptor using validated SID strings:

```text
D:(XA;;GA;;;WD;(Member_of {SID(<server-account-SID>), SID(<server-service-SID>)}))
```

This `Member_of` list requires both identities. Two ordinary allow ACEs would grant an OR instead. `QOS.Sid` is not the complete service identity check; keep the V5 descriptor. The MUTUAL_AUTH capability alone is insufficient because an SSP can report negotiation differently from the application's identity requirement. See [V5 QOS semantics](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v5_w).

Set unused/reserved fields to their documented zero values. Check every creation/option/bind result before use. Bind, make only the intended calls, unbind before freeing, then release policy allocations. An async bind's completion uses `RpcAsyncGetCallStatus`; a procedure's completion uses `RpcAsyncCompleteCall`. Never release still-referenced stack state, buffers, events, or policy data on cancellation.

Fast `RpcBindingBind` bindings do not support server-initiated RPC callbacks. Do not add `[callback]` IDL. DONTLINGER and unique-binding options do not prove process-wide security-cache eviction; test identity variation in separate processes and fixed-policy coexistence in the real hosting model.

## Server registration

Before exposing an endpoint, verify the process account/service identity and install a deny-all `RpcMgmtSetAuthorizationFn` hook for unused runtime management operations. Its scope is process-wide and must be reviewed against cohosted interfaces.

Register WINNT authentication with `RpcServerRegisterAuthInfoW`. Use `RpcServerUseProtseqEpW` for `ncalrpc`, and `RpcServerRegisterIf3` with an explicit protected descriptor and authorization callback. Both endpoint and application-interface descriptors admit the caller service SID:

```text
D:P(A;;GA;;;<caller-service-SID>)
```

Require all these interface flags:

```text
RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY |
RPC_IF_ALLOW_SECURE_ONLY | RPC_IF_SEC_NO_CACHE
```

The interface ACL is checked before the callback. LOCAL_ONLY is not itself a protocol check; SECURE_ONLY is not service authorization. SEC_NO_CACHE controls application security-callback caching, not every Windows security cache. AUTOLISTEN allows draining/unregistering the owned interface without process-wide listener shutdown.

Keep descriptors alive as required by registration. Drain/unregister only the owned interface before dropping callback state. Endpoint and management policy can remain process-scoped; do not stop unrelated provider or COM interfaces.

## Per-call authorization before unmarshaling

In the registered callback, query `RPC_CALL_ATTRIBUTES_V2_W` with `Version = 2` and `Flags = RPC_QUERY_IS_CLIENT_LOCAL`. Reject query failures or any mismatch:

| Attribute | Require |
| --- | --- |
| `ProtocolSequence` | `RPC_PROTSEQ_LRPC` |
| `IsClientLocal` | `rcclLocal` |
| `NullSession` | false |
| `AuthenticationService` | `RPC_C_AUTHN_WINNT` |
| `AuthenticationLevel` | At least `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` |

Then call `RpcGetAuthorizationContextForClient` with `ImpersonateOnReturn = FALSE`, reserved pointer arguments NULL, reserved scalar arguments zero, and zero reserved LUID. Do not attach a client token to the executing thread.

Query `AuthzContextInfoUserSid` and `AuthzContextInfoGroupsSids`. The user SID must equal the expected account exactly. The expected service SID must be present with `SE_GROUP_ENABLED` and without `SE_GROUP_USE_FOR_DENY_ONLY`. Merely being SYSTEM, LocalService, Administrator, or a member of a broadly allowed group is insufficient. Repeat this check in each manager before returning success or dispatching work.

For a caller policy requiring restricted-token membership, query `AuthzContextInfoRestrictedSids`. If the restricting list is nonempty, require the expected service SID there too, including for WRITE_RESTRICTED tokens. Keep native ACL checks in force; this identity policy is not a synthetic access check or a claim of complete sandbox isolation. For BFD startup identity, additionally verify the write-restricted marker as specified by the service profile.

Cap queried buffers (BFD baseline: 1 MiB), initialize aligned storage, and validate returned sizes, count arithmetic, embedded pointer containment/alignment, SID revision/count, and complete subauthority bounds before SID APIs. For an empty variable-length group list, accept only the documented count/header layout; do not require storage for a nonexistent first element. Fail closed on malformed or oversized results. Always release the RPC-supplied context with `RpcFreeAuthorizationContext`, not `AuthzFreeContext`.

## Wire contract, quotas, and deadlines

Generate MIDL with `/nologo /env x64 /robust /Oicf /app_config`, separate `/client stub /server none` and `/server stub /client none`, explicit `/prefix`, `/h`, `/out`, and client `/acf` for asynchronous procedures. Use explicit handles, fixed integer fields/arrays, versioning, and `[range]` constraints. Avoid unbounded strings, attacker-sized allocations, and caller-supplied privileged targets.

Application-level permits and bounded nonblocking queues provide the hard work bound; interface `MaxCalls` is best effort and `MaxRpcSize` is ignored for local RPC. `RPC_C_OPT_CALL_TIMEOUT` is ignored for LRPC. Use native async notification, explicit deadlines, cancellation, and confirmed completion instead. Keep output, async state/event, binding, and referenced security allocations alive throughout cancel/drain/unbind/free.

Define a finite supervision budget and a process-specific uncertain-ownership policy. Retain at most the planned worker(s), quarantine/mark telemetry unavailable, or terminate the affected process if safe lifetime cannot be maintained. Never free an active native stack, use forced thread termination, or create unbounded replacement workers. Authenticate each functional call independently rather than relying on a prior connection check.

## Negative test matrix

| Scenario | Required outcome |
| --- | --- |
| Correct account and enabled service SID, correct server pin | Authorized operation succeeds. |
| Correct account, wrong/missing/disabled/deny-only service SID | Reject. |
| Correct service SID, wrong account | Reject. |
| Restricting list present without required caller service SID | Reject under the restricted-caller policy. |
| Anonymous/null session, wrong transport, weak/wrong authentication | Reject before application arguments are accepted. |
| Same endpoint replaced by server missing required account/group | Client rejects; recover when the valid server returns. |
| Runtime interface enumeration, principal query, statistics, listener state, stop | Deny independently of the application ACL. |
| Malformed wire record | Reject completely; clear stale telemetry and retry with bounded backoff. |
| Timeout/cancellation/late bind completion | No early release, no fabricated result, bounded supervision. |
| BGP request canceled/expired while queued | Skip privileged execution. |
| Real read-only provider traffic with fixed-policy RPC in the same process | Preserve COM/MI behavior and reject a wrong server. |

Use fresh-process fixtures for varying identity policies. Test real SCM identities separately on disposable installed-service runners; normal-user fixtures do not establish installed-token correctness.

## Primary references

- [RpcBindingBind and callback limitations](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingbind)
- [Interface ACL registration](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3)
- [Interface registration flags](https://learn.microsoft.com/en-us/windows/win32/rpc/interface-registration-flags)
- [Call attributes V2](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/ns-rpcasync-rpc_call_attributes_v2_w)
- [RPC authorization contexts](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcgetauthorizationcontextforclient)
- [RPC Authz context release](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcfreeauthorizationcontext)
- [Authz information classes](https://learn.microsoft.com/en-us/windows/win32/api/authz/ne-authz-authz_context_information_class)
- [RPC runtime management authorization](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcmgmtsetauthorizationfn)
- [Local timeout option limitations](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingsetoption)

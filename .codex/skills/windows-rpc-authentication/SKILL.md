---
name: windows-rpc-authentication
description: Implement, audit, or document authenticated local Windows service RPC over ncalrpc. Enforces server identity pinning, exact caller account and enabled service SID, protected interface ACLs, per-call Authz checks without impersonation, bounded async lifetimes, and directed call initiation. Not a remote TCP RPC or generic NTLM recommendation.
---

# Windows local RPC authentication

Use this skill for private Windows service-to-service `ncalrpc` channels. Read [the complete authentication policy](references/authentication-policy.md) before changing a binding, endpoint, interface registration, authorization callback, or related test. Read [the BFD channel profile](references/bfd-channel-profile.md) for the concrete two-service configuration from which this skill was extracted.

## Establish the policy before editing

Identify the initiator, receiving endpoint, exact account SID and service SID on both ends, minimum supported Windows version, wire operations, privileged target source, and shutdown/cancellation ownership. Inspect both code and deployment configuration. Reuse a checked common security policy for parallel channels; do not weaken one channel for convenience.

For these local private channels require explicit `ncalrpc`, WINNT authentication, packet privacy, static Identify/effective-only credentials, V5 server identity checks, protected service-SID ACLs, and per-call account-plus-group authorization. There is no transport downgrade, anonymous fallback, endpoint-name trust, account-only acceptance, or administrative-group bypass.

If asked to extend this to remote RPC, establish a separate threat model and authentication policy; do not carry a local WINNT policy onto TCP or claim `ncalrpc` is a remote transport. V5 needs Windows 8/Server 2012 or later; fail closed on an unsupported platform instead of silently dropping identity checks.

## Enforce independent gates

1. Verify the service's own process account and enabled, non-deny-only service SID before opening configured resources or registering endpoints. Verify required restricting SIDs for restricted service roles.
2. Configure a fixed local endpoint and protected endpoint/interface ACL admitting only the expected caller service SID.
3. Authenticate the server using the expected account **and** service SID in the V5 descriptor. The mutual-authentication flag, account SID, or endpoint name alone is insufficient.
4. Require local actual protocol, authentication service/level, and non-null-session attributes for every call. Disable callback caching and repeat application authorization in each manager.
5. Obtain a native Authz context with `ImpersonateOnReturn = FALSE`. Require exact user account equality and enabled/non-deny-only service group membership; apply restricted-SID policy where specified. Release with `RpcFreeAuthorizationContext`.
6. Deny unused RPC runtime management operations through their separate authorization hook. Review the hook's process-wide impact when hosting other interfaces or COM/MI.

Treat every gate as necessary. An ACL check is not a substitute for the application's account-plus-service identity policy; an authenticated identity is not permission to select arbitrary privileged operations or targets.

## Preserve direction and least privilege

Model call initiation separately from response data. A broker-to-service probe is initiated only by the broker; a service-to-broker control channel is initiated only by the service. Each ordinary RPC request can return a response. Do not describe this as a data diode, change it into one-way IDL semantics, or remove results needed for authentication/liveness.

Use separate explicit client/server roles and no remote `[callback]` procedures. A local RPC runtime security callback is an authorization hook, not a reverse RPC call. Label diagrams `ncalrpc` and point each initiation arrow from its client to its server. Native `RPC_PROTSEQ_LRPC` means this same local RPC mechanism, not an alternate weaker transport.

Do not call `ImpersonateNamedPipeClient`, `RpcImpersonateClient`, open a peer process to infer identity, or grant `SeImpersonatePrivilege`/`SeDebugPrivilege` for these channels. Keep provider execution under the privileged broker's configured identity, with the fixed operation target loaded from protected configuration.

## Bound work and failure

Use robust generated stubs, fixed-width bounded records, declared ranges, and explicit binding handles. Validate application semantics once after unmarshaling. No caller-selected executable, command, path, peer, or BGP target belongs in the privileged control request.

Use application queue/permit limits: `MaxCalls` is advisory, and `MaxRpcSize` is ignored for `ncalrpc`. Keep provider work serialized on a bounded worker, cancel/expire queued requests before execution, and avoid holding packet-path locks.

Use real asynchronous deadlines and completion-before-release. A local call-timeout option, dropped future, cancellation request, or elapsed deadline does not prove completion. Keep the binding, async state/event, wire buffers, SID, descriptor, and callback state alive until native ownership ends. Bound retries and retain at most the documented number of workers. A timed-out privileged action can have executed; return an unknown outcome rather than blindly retrying it.

## Verify the policy, not just happy-path connectivity

Exercise authorized calls and rejection of anonymous callers, wrong accounts, missing/disabled/deny-only service groups, unexpected restricting lists, wrong protocol/authentication settings, replacement servers at the same endpoint, and every blocked management operation. Verify recovery after rejection and clean transport failures, cancellation, bounded shutdown, and malformed records.

Use process-isolated token fixtures for differing expected identities so RPC's process-wide security caches do not make the test misleading. Also test the actual fixed-policy client alongside read-only provider traffic in the shared host. Neither unique binding nor DONTLINGER promises a global authentication cache flush.

Use disposable installed-service CI to verify real SCM-issued accounts/SIDs and restricted tokens after install/repair. Local fixture tests use their own account/groups and reduced tokens; do not grant them installed-service identity or mutate a developer's live SCM/RRAS configuration. Report fixture coverage separately from installed-service evidence.

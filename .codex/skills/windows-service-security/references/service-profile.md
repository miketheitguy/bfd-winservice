# BFD service identity and provider profile

This concrete profile records bfd-winservice's security decisions. Reusing the skill for a different service requires selecting and verifying that service's own identities, required privileges, and provider policy.

## Accounts, SIDs, and privileges

| Role | Required process identity and restrictions |
| --- | --- |
| `BfdWinService` | LocalService (`S-1-5-19`), enabled/non-deny-only `NT SERVICE\BfdWinService` group, SCM restricted service SID type `3`. Restricting SIDs include its service SID and WRITE_RESTRICTED marker `S-1-5-33`. |
| `BfdBgpBroker` | LocalSystem (`S-1-5-18`), enabled/non-deny-only `NT SERVICE\BfdBgpBroker` group, unrestricted service SID type `1`. Startup permanently retains only `SeChangeNotifyPrivilege` before COM/MI, target loading, or RPC registration; provider calls use its own SYSTEM account. |

BFD's SCM `RequiredPrivileges` allowlist is `SeChangeNotifyPrivilege` and `SeCreateGlobalPrivilege`. Its startup permanently removes unused privileges, including `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege`, before loading configuration, opening sockets, or registering RPC. Removal is not just disabling, and it does not remove account/group memberships. Query process tokens without attaching client tokens to threads.

Verify the write-restricted lists explicitly at service startup. WRITE_RESTRICTED imposes an additional restricting-token check for applicable writes; reads retain normal ACL semantics. It does not turn LocalService into a complete sandbox. A console run retains its launching identity and does not reproduce the installed service boundary or BGP control.

## Object permissions

| Object | Required policy |
| --- | --- |
| SCM service configuration/controls | SYSTEM and Administrators manage the service. Authenticated non-administrators can query/interrogate/read the service ACL, not start, stop, reconfigure, or send private custom controls. |
| Installed executable/library directory | SYSTEM/Administrators control writes; ordinary users receive only required read/execute access. Do not grant the network service write access to its executables or DLL search locations. |
| `HKLM\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters` | SYSTEM/Administrators control writes; BFD service SID reads; ordinary users cannot read authentication keys. Broker reads its fixed BGP target under its management identity. |
| Private `ncalrpc` endpoint/interface | Protected descriptor admits only the expected caller service SID, plus exact account/group checks on every call. |
| Default file logs | SYSTEM/Administrators control; BFD service SID has Modify access; users read under the intended log policy. Custom paths need explicit service-SID access to folder, active file, and rotated file. |
| Windows event channel | Respect the actual manifest/Windows channel permissions; do not claim a custom channel ACL if none was provisioned. |

Read/status visibility is distinct from private-control access. Deny secret disclosure while keeping useful nonsensitive observability.

## Untrusted packet boundary

Keep kernel program-specific UDP firewall rules and application validation as separate gates. Validate configured source/destination, ports, interface, TTL/hop limit, packet structure, and session discriminators before accepting peer state. Path checks do not authenticate a peer.

BFD wire authentication defaults to `none`, but classical multihop with `BgpPeerName` requires `meticulous-sha1` and a valid key, even with `MinTtl`. Single-hop BGP without authentication warns that it relies on a trusted link. Never describe an unauthenticated deployment as shared-key authenticated. An enabled mode requires matching type, key ID, and secret on both peers. Reject failed authentication without refreshing detection or changing accepted session state. Compare passwords/keyed digests in constant time and keep key material out of diagnostics.

The compatibility modes have distinct limits: simple-password sends its secret in cleartext and has no sequence protection; keyed SHA-1 modes use protocol-defined keyed digests, not HMAC or encryption. MD5 configurations and wire types 2 and 3 are rejected; SHA-1 retains wire types 4 and 5. Classical keyed modes enforce a receive window; meticulous SHA-1 additionally rejects repeated sequences. Do not silently substitute an incompatible algorithm while claiming wire compatibility. S-BFD initiators match replies to unconsumed, unexpired outstanding probes; reflectors verify and echo keyed request sequences without claiming a classical per-peer receive window.

When authentication is enabled, configure exactly one of ASCII `AuthKey` and binary `AuthKeyHex`. Password keys are 1-16 bytes and SHA-1 keys are 1-20 bytes, with key ID 0-255. One key is active at a time and authentication changes require restart. Registry ACLs protect stored keys; there is no application-level at-rest encryption. A valid shared-key check proves secret possession, not a distinct per-peer certificate or Windows identity. Authentication choices and their risks remain explicit deployment decisions.

## COM and local MI provider

Initialize the broker's COM security once, before MI/provider use. Its access descriptor is:

```text
O:SYG:SYD:(A;;0x3;;;SY)
```

Supply the absolute descriptor in the format `CoInitializeSecurity` requires; keep its backing SID/ACL storage alive until the API has copied it. Require non-null owner, group, and DACL. Check all conversion results.

Preserve these settings:

| API/policy | Required setting |
| --- | --- |
| `CoInitializeSecurity` authentication | `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` |
| Default proxy impersonation | `RPC_C_IMP_LEVEL_IDENTIFY` |
| Capabilities | `EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL` |
| `IGlobalOptions` exception handling | `COMGLB_EXCEPTION_DONOT_HANDLE_ANY` |
| `IGlobalOptions` unmarshaling | `COMGLB_UNMARSHALING_POLICY_STRONG` |
| Local MI destination impersonation | Explicit IMPERSONATE for the provider to execute under the broker's own SYSTEM identity; do not substitute the BFD caller token. |

The MI setting is not a reason to weaken the separate private `ncalrpc` binding's Identify-only credentials. Do not relax provider policy globally when adding a new local interface. Treat unexpected `RPC_E_TOO_LATE`/unknown prior initialization as a failure rather than silently proceeding. Process-wide runtime-management denial also needs a coexistence check.

## Installation, recovery, and testing

Provision required privileges while services remain stopped and before normal first start. Preserve unknown/empty prior settings in rollback snapshots instead of inferring a default. Repair must retain identity, ACLs, required privileges, dependency/recovery policy, and protected configuration. Security setup must fail closed if it cannot be applied.

Use local token fixtures for authorization logic and disposable hosted MSI tests for real service-account handshakes after start and repair. Do not install services or manipulate live BGP/RRAS state to validate a documentation/skill change. Use a read-only provider coexistence test to validate that local RPC did not disrupt COM/MI hosting. Distinguish test tokens from SCM-issued service tokens in the report.

Use final executable checks for compiler/linker mitigations. Configure SEHOP separately where the supported deployment policy requires it, and verify its Windows setting rather than claiming `/SAFESEH` protects x64. A CET-compatible image still requires supported Windows/hardware and enforcement policy.

## Primary references

- [Restricted token write semantics](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [Service configuration APIs](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
- [COM process security](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity)
- [COM global options](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-iglobaloptions)
- [SEHOP exploit protection](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference#validate-exception-chains-sehop)

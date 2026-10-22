# BFD two-channel security profile

These names, account assignments, record sizes, and timing values describe bfd-winservice. Treat them as a concrete reuse profile; derive a new application's identities and budgets rather than copying these names as universal defaults.

## Directed calls and authenticated identities

| Initiator to receiver | Endpoint and operations | Client identity required by server | Server identity pinned by client |
| --- | --- | --- | --- |
| Broker telemetry worker to BFD | `BfdWinService.Local.v2`; `BfdLocal` 2.0, `GetSessionStatusV1` only | LocalSystem (`S-1-5-18`) AND enabled `NT SERVICE\BfdBgpBroker` SID, plus required membership when a restricting list exists | LocalService (`S-1-5-19`) AND enabled `NT SERVICE\BfdWinService` SID |
| BFD control worker to broker | `BfdWinService.Bgp.v2`; `BgpControl` 2.0, Get/Start/Stop | LocalService AND enabled `NT SERVICE\BfdWinService` SID, plus required membership when a restricting list exists | LocalSystem AND enabled `NT SERVICE\BfdBgpBroker` SID |

Both transports are `ncalrpc`. Both apply the same binding authentication and protected registration policy; each substitutes the appropriate roles. Both channels also require the expected caller service SID in any nonempty restricting list, including WRITE_RESTRICTED tokens; an unrestricted caller still needs the exact account and enabled service group. The BFD process has a restricted service SID; the broker's service SID is unrestricted. Neither channel initiates calls in its reverse direction, and neither has remote callbacks. Responses travel within the initiated call.

The session-status contract uses a fixed 336-byte x64 native record. The BGP result is a fixed eight-byte record containing 32-bit provider status and Boolean value fields. BGP opcodes are range-bounded `1..3`; Boolean results are `0..1`. The control request carries no BGP peer/target, path, command, or secret. The broker selects the fixed target from protected configuration.

## Supervision and health meaning

The services start independently. BFD has no SCM service dependencies; only the broker depends on RpcSs for native MI. Neither service verifies its counterpart at startup. Both verify their own installed identity before registering endpoints, and functional calls authenticate their peer independently. A missing BFD leaves telemetry unavailable with retries; a missing broker leaves pending BGP actions retrying while the packet engine continues.

Telemetry binds and calls each have a two-second native deadline, with an eight-second supervisor budget. Healthy polling is one second. Clean failures discard stale status and use bounded exponential backoff (1, 2, 4, 8, 16, then 30 seconds) and rate-limited diagnostics. Uncertain native ownership retains one parked worker and quarantines telemetry; no replacement-worker loop is allowed.

BGP control uses a finite total operation budget with a bounded native cancellation drain. Its worker is joined on shutdown; unresolved ownership aborts the BFD process to preserve native stack lifetime. Do not propagate this abort policy to the broker's telemetry supervisor. Inspect the implementation's exact current constants before changing timing or making operational claims.

BGP control sends no startup or idle connection probes, tracks no broker instances, and does not replay completed actions after a restart. Each functional call independently authenticates and authorizes its peer. Outstanding failed actions retain their ordinary retry policy. Telemetry failure never authorizes a BGP action. A timeout on Start/Stop can leave an unknown action outcome. Discard canceled/expired queued requests before dispatch, and reconcile already-dispatched work through the defined operation contract.

## Regression evidence

Use disposable account/group fixtures to verify both channels, including anonymous callers, server replacement, restricting-list rejection, management denial, native cancellation, and recovery. Keep read-only RPC/MI coexistence coverage in the broker process. Run actual service-account/SID handshake checks after MSI start and repair only on the disposable installation runner. Do not retrofit a test account with installed service SIDs or change a workstation's live RRAS state.

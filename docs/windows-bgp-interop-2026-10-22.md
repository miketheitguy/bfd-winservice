# Windows BGP withdrawal and recovery validation

This record describes a Hyper-V lab test of Windows-controlled BGP withdrawal
and recovery on 2026-10-22. It includes the failures found in v2.0.1 and the
regression results for the fixes released in v2.0.2.

## Lab and isolation

- Windows Server 2025 Standard Evaluation runs BfdWinService, BfdBgpBroker,
  and RRAS BGP. Its address is `172.27.234.142`, ASN is 64513, and peer name
  is `BirdLab`.
- Ubuntu 26.04.1 runs BIRD 2.18 at `172.27.229.113`, ASN 64512.
- BIRD advertises `203.0.113.54/32`; Ubuntu also owns this address on loopback.
  Windows learns the prefix through `BirdLab` and installs it in ActiveStore
  with protocol `Bgp` and next hop `172.27.229.113`.
- Windows advertises its anycast address, `198.51.100.53/32`, in the opposite
  direction. Both peers disable BGP graceful restart and use a 90-second hold
  time.
- BFD uses meticulous keyed SHA1, key ID 23, 500 ms transmit/receive intervals,
  and a detection multiplier of 3. The negotiated detection time while Up is
  1.5 seconds. No keys or credentials appear in this record.

Windows has `BgpPeerName=BirdLab`. BIRD's BGP protocol has `bfd off` during the
isolated Windows-control measurements; its standalone BFD session remains
enabled. A temporary nftables table drops only UDP destination port 3784
between these two addresses, in both directions. TCP port 179 and SSH remain
available. Each cycle removes its own table and checks that BFD packets hit
the drop counters. Ubuntu management uses SSH with a pinned host key.

## Failures in v2.0.1

The installed release stopped the Windows BGP peer and removed the route from
both Windows tables after BFD timed out. After removing the fault, BFD reached
Up, but the peer remained Stopped and the route remained absent throughout the
15-second recovery observation.

The Windows `BFD-Service/Operational` log identified two provider compatibility
defects:

1. Status queries required `ValueMap` and `Values` qualifiers on
   `BgpPeerConfig.ConnectivityStatus`. The actual RRAS class exposes only a
   `read` qualifier, producing event 301 with
   `read BGP status enum qualifier: MI_Result=6`.
2. A successful Stop returned an empty method-result instance. Requiring a
   `ReturnValue` property logged event 301 with
   `read CIM ReturnValue: MI_Result=12`, even though Windows had stopped the
   peer. The controller consequently retried the action.

The fix uses the status contract in Microsoft's installed
`RemoteAccess/PS_BgpPeer_v1.0.cdxml`: Idle=1, Connecting=2, Connected=3, and
Stopped=4. Unknown values remain errors. Start and Stop accept absent method
output only after successful MI completion and a subsequent status query that
confirms the requested peer state. Explicit invalid or nonzero return values
remain errors. A status query still requires a valid zero return and exactly
one peer.

## Windows-controlled BFD results

The fixed production-profile broker ran with the installed service identities
and executable ACLs preserved. The baseline remained BFD Up, BGP Connected,
and the /32 present in both Windows tables for 120.620 seconds without a
service restart. Three subsequent fault cycles passed:

| Cycle | SSH fault acknowledgment received to observed Stop and both withdrawals | BFD Down event to successful Stop event | BFD Up event to successful Start event | SSH fault-removal acknowledgment received to observed BGP and route recovery |
| --- | --- | --- | --- | --- |
| 1 | 1.782 s | 9.074 ms | 17.088 ms | 7.936 s |
| 2 | 2.162 s | 9.673 ms | 14.150 ms | 5.256 s |
| 3 | 1.986 s | 8.203 ms | 14.853 ms | 6.500 s |

The end-to-end columns start when the host receives each SSH acknowledgment.
They are polling observations that include management and sampling overhead,
not packet-level withdrawal timestamps or measurements from the instant the
fault rule was applied. Event deltas use timestamps from the
same Windows guest. Start confirms that the peer is enabled; BGP establishment
and route installation take longer.

Each cycle required these event messages, in the corresponding order:

| Event | Required message or meaning |
| --- | --- |
| 103, Warning | Local BFD Down with `Control Detection Time Expired` |
| 201, Warning | Detection expiry, including the negotiated detection time |
| 300, Information | `BGP broker peer="BirdLab" method=Stop result=Ok(0)` |
| 102, Information | Local BFD Up after recovery |
| 300, Information | `BGP broker peer="BirdLab" method=Start result=Ok(1)` |

While loss persisted, the peer stayed Stopped and both routes stayed absent.
After recovery, both routes returned through the expected next hop. There were
no service restart, authentication failure (105), or broker failure (301) events
within the measured cycles. Historical v2.0.1 failure events remain in the log.

## BGP-only results

Two additional checks ran with BFD continuously Up:

| Change on BIRD | Windows result |
| --- | --- |
| Disable and re-enable the static /32 origin | Both route tables remove the prefix, then reinstall it; BGP stays Connected |
| Disable and re-enable the BGP protocol | Both route tables remove the prefix; the Windows peer becomes Connecting, then returns to Connected and reinstalls the prefix |

Neither check produced a Windows BFD Down event, a broker error, or a Windows
Stop/Start management action. Windows therefore distinguishes BGP reconnection
from BFD failure rather than administratively stopping a healthy BFD peer.

## Regression coverage and evidence

Native MI fixtures cover all four published status values, unknown values,
embedded peer arrays with zero, one, or multiple results, valid and invalid
return types/codes, missing action output, and state-verification failures.
The opt-in `native_mi_reads_configured_rras_peer` test exercises the real RRAS
Get method without changing the peer. See [development checks](../CONTRIBUTING.md#run-development-checks).

Local checks passed for v2.0.2: the complete native test suite, strict Clippy,
formatting, strict API documentation, production executable hardening, and
offline bundle/MSI validation. The read-only RRAS fixture also passed inside
the Windows guest. Installed-service tests restricted to GitHub-hosted runners
remain part of the release workflow rather than this local fixture run.

The local evidence directory is
`target/bird-interop/windows-withdrawal/`. Its JSON files contain the original
failure, the provider/CDXML contract, fixed-build hashes, timestamped route
samples, and complete rendered events. `Test-Reverse.ps1` and
`Test-BgpOnly.ps1` reproduce the lab checks using the existing protected VM
credentials and SSH configuration; their addresses and peer names are specific
to this lab. These ignored artifacts are not portable test infrastructure.

These results cover this Windows Server 2025 and BIRD 2.18 pairing. They do not
establish timing guarantees for other providers, operating systems, virtual
switches, or hardware.

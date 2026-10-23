# Installed resources and firewall rules

Donatello's deployment inventory, dude. Use this reference to inspect what the
offline setup bundle provisions. For installation commands, follow
[Set up a BFD session](../setup.md). For exact token and ACL boundaries, see
[service isolation](../security/service-isolation.md).

## Installed resources and security settings

Donatello would inspect the full installation inventory, dude. The bundle installs
the following resources for all users:

- Both executables, the manifest, `Initialize-Logging.ps1`, and
  `Set-BfdAuthenticationKey.ps1` in
  `C:\Program Files\BfdWinService`.
- The `BfdWinService` service with display name **BFD Windows Service**,
  the LocalService account, and **Automatic (Delayed Start)** startup. The bundle
  leaves it stopped; configure it before starting the service or restarting
  Windows. Delayed start runs after boot-time services, when interface addresses
  are more likely to be assigned.
- The `BfdBgpBroker` service with **Automatic (Delayed Start)** startup and the
  LocalSystem account. Both services start independently; neither depends on the
  other. Without `BgpPeerName`, BFD doesn't start its BGP control worker. The
  broker still queries BFD's private RPC status interface. Both services have their
  own enabled service SID. BFD uses restricted SID type `3`; its service SID is
  also present in the token's restricting list. The broker retains unrestricted
  SID type `1`.
- A `RequiredPrivileges` allowlist for each service containing only
  `SeChangeNotifyPrivilege`. A native commit action records both lists after the
  MSI transaction succeeds; services remain stopped
  until you start them. SCM applies each list when it creates the service
  process. Both services validate the actual token at startup and refuse unexpected
  privileges before opening network sockets or initializing COM/MI and RPC.
- Protected service ACLs for both services: SYSTEM and Administrators have full
  control. Authenticated users can query configuration/status, enumerate
  dependents, interrogate status, and read the service ACL. They cannot Start/Stop,
  pause, reconfigure, delete, or send custom controls to either service. Use an
  elevated Administrator session for lifecycle commands. Log reads remain
  available to non-administrators under the existing log permissions.
- SCM recovery: the broker restarts five seconds after a crash. BFD restarts
  10 seconds after a crash or an unrequested failure exit, such as a local address
  that isn't assigned yet. A Stop request always ends BFD with exit code `0`, so
  those requests do not queue another recovery restart. A restart queued by an
  earlier failure can still occur after a manual start and stop; see
  [SCM queued restart behavior](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w).
- The `BFD-Service` provider and enabled `BFD-Service/Operational` channel,
  with message and resource paths pointing to the installed executable.
- The Parameters key with `Multihop` DWORD `0`, `LogToFile` DWORD `0`, and
  `LogFilePath` string `C:\ProgramData\BfdWinService\trace.log` on a default
  Windows layout. The installer uses the machine's ProgramData location. The
  executable fallback and logging script use the literal `C:\ProgramData` path.
- The `Parameters\Secrets` key with its own protected ACL and an installer policy
  marker. SYSTEM owns the key; SYSTEM and Administrators have full control
  (`0x000F003F`), and `NT SERVICE\BfdWinService` has read access (`0x00020019`).
  These explicit grants inherit to child keys; inheritance from the parent is
  blocked. No authentication key is supplied by the installer. Use the installed
  [key administration tool](../configuration.md#authentication-key-administration)
  to set `AuthKeyDpapi` as `REG_BINARY` ciphertext. Repair reapplies the ACL and
  preserves that value.
- The ProgramData `BfdWinService` folder, without creating or writing `trace.log`.
  Only the BFD service SID receives Modify access; shared LocalService processes
  receive no write grant. The Parameters key permits reads only by SYSTEM,
  administrators, and that service SID. BFD's write-restricted token requires
  suitable service-SID grants as well as ordinary write permission. Installed
  code remains writable only by
  SYSTEM and administrators.
- Five executable-specific UDP allow rules for classical and Seamless BFD.
- The broker's `RpcSs` service dependency for native MI. BFD has no SCM service
  dependencies. See [Monitor service status and BFD events](../monitoring.md) for
  lifecycle queries and event-log monitoring.

## Installed firewall rules

Keep the network entrance totally tubular and check the actual rules. Five rules
allow UDP for the installed executable on Domain, Private, and Public profiles.
Remote addresses are unrestricted so multihop, anycast, and point-to-point
configurations can use their configured peers. The rules have these protocol and
port restrictions:

| Rule | Protocol / action | Direction | Local ports | Remote ports |
| --- | --- | --- | --- | --- |
| `BfdWinService - control inbound` | UDP / allow | Inbound | 3784, 4784 | 49152–65535 |
| `BfdWinService - S-BFD requests inbound` | UDP / allow | Inbound | 7784 | 1–7783, 7785–65535 |
| `BfdWinService - S-BFD replies inbound` | UDP / allow | Inbound | 49152–65535 | 7784 |
| `BfdWinService - probes outbound` | UDP / allow | Outbound | 49152–65535 | 3784, 4784, 7784 |
| `BfdWinService - S-BFD replies outbound` | UDP / allow | Outbound | 7784 | 1–7783, 7785–65535 |

The high-port inbound rule is required for S-BFD initiators because replies
return to their source port. Reflectors accept requests from any nonzero source
port except 7784 and reply to that same port; their separate rules preserve
the classical dynamic-source-port restriction. No BFD Echo rule is installed. Network firewalls
and organizational policy still control effective access. The private local RPC
interface uses `ncalrpc` and needs no network firewall rule.

To inspect the installed rules, run:

```powershell
Get-NetFirewallRule |
    Where-Object DisplayName -Like 'BfdWinService - *' |
    Select-Object DisplayName, Direction, Enabled, Profile
```

Firewall vibe check: confirm that the five rules are enabled. To inspect ports,
pipe the matching rules to `Get-NetFirewallPortFilter`.

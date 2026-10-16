# BFD Windows service

For Windows network administrators, this service runs a Bidirectional Forwarding
Detection (BFD) session with one IPv4 or IPv6 peer, or a stateless Seamless BFD
reflector for multiple initiators. Follow this guide to install and configure the
service. Optional Border Gateway Protocol (BGP) control starts and stops a
configured Windows BGP peer as session state changes.

The BFD service runs as LocalService with a restricted service SID. A separate
LocalSystem broker manages BGP through a local pipe restricted to the BFD service
identity. The broker also
queries BFD session status through a private Windows local RPC interface with
mutual service authentication. Queries read published snapshots on RPC workers,
independently of packet processing.

For probes that establish without a discriminator handshake, configure an
IPv4/IPv6 [Seamless BFD initiator or reflector](docs/seamless.md).

The service uses these Windows names:

| Name | Value |
| --- | --- |
| Windows service | `BfdWinService` |
| BGP management service | `BfdBgpBroker` |
| Event provider | `BFD-Service` |
| Event Log channel | `BFD-Service/Operational` |

## Before you begin

You need:

- 64-bit Windows 10 or later, or Windows Server 2016 or later, on an
  x64 processor.
- An x64 MSI from
  [GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases),
  or matching `bfd-winservice.exe` and `Initialize-Logging.ps1` files supplied
  by your service maintainer for console execution.
- Administrator PowerShell access to install the MSI and configure registry settings.
- A local IP address, its interface index, and a remote BFD peer that you can
  configure. See [network requirements](docs/protocol.md).

## Quick start

Use **PowerShell as Administrator** for installation and configuration.

### 1. Install the service

Follow [Install with an MSI](docs/setup.md#install-with-an-msi) to install the
files and Automatic (Delayed Start) services, register the Operational provider, and create
firewall rules. The service remains stopped for configuration.

Supplied loose files support [foreground console execution](docs/setup.md#run-in-a-console).
Use the MSI for service execution and BGP management.

### 2. Configure a fresh installation

Follow [Configure the session](docs/setup.md#2-configure-the-session) to provision
the required registry values. Before the first start,
[enable SEHOP](docs/setup.md#enable-sehop-for-the-executable) for the executable.

The default transport is single-hop. File output defaults to disabled; on a
default Windows layout, its path is `C:\ProgramData\BfdWinService\trace.log`.

### 3. Start the service

In **PowerShell as Administrator**, start the configured service:

```powershell
Start-Service BfdWinService
```

The command returns without output on success.

## Verify the session

Check the Windows Service Control Manager (SCM) status:

```powershell
Get-Service BfdWinService | Select-Object Name, Status
```

A successful startup reports:

```text
Name          Status
----          ------
BfdWinService Running
```

The startup vibe check has two parts. SCM `Running` confirms engine startup.
For a classical session or S-BFD initiator, configure the remote peer and confirm
event `102` in `BFD-Service/Operational` to verify BFD reached `Up`. A stateless
reflector has no per-peer `Up` state; verify replies from an initiator instead.
See [Verify peer communication](docs/setup.md#6-verify-peer-communication)
for the query and expected events.

Use Windows lifecycle queries and event logs for monitoring. The private local
RPC interface between BFD and the broker provides an authenticated connection
probe and read-only session telemetry for the broker; it exposes no
administrative status client. See
[Monitor service status and BFD events](docs/monitoring.md).

Non-administrators can query service status. Log reads depend on the host's
Event Log and filesystem permissions. Start/Stop and configuration changes
require an elevated Administrator; SYSTEM retains Windows service lifecycle
access.

With BGP control enabled, initial BFD negotiation leaves BGP unchanged. After BFD
reaches `Up`, a path failure can stop the configured peer. Administrative
disablement at either end releases a Stop previously issued by BFD; it does not
stop BGP. See the [BGP action rules](docs/bgp.md) before connecting a production
peer.

For foreground execution that writes to standard output (STDOUT), see
[Run in a console](docs/setup.md#run-in-a-console). The executable accepts
`--console`, `--help`, and `--version`; session configuration comes from
registry values.

## Documentation

Use these guides for the next task:

| Task | Guide |
| --- | --- |
| Install, configure, verify, or stop a session | [Set up a BFD session](docs/setup.md) |
| Look up registry values, defaults, and authentication | [Registry configuration reference](docs/configuration.md) |
| Configure an S-BFD initiator, reflector, or anycast target | [Configure Seamless BFD](docs/seamless.md) |
| Enable file output or interpret Operational events | [Logs and events](docs/logging.md) |
| Connect BFD state changes to a Windows BGP peer | [Control a Windows BGP peer](docs/bgp.md) |
| Query service status and read BFD state events | [Monitor service status and BFD events](docs/monitoring.md) |
| Check ports, firewall requirements, and protocol limits | [Network and protocol behavior](docs/protocol.md) |
| Understand authentication, privilege boundaries, and compiler/linker protections | [Security, authentication, and build hardening](docs/security.md) |
| Trace service inputs, outputs, and BGP actions | [Service communication](docs/service-communication.md) |
| Review the RPC identity checks, privileges, and security guidance | [Local RPC authentication and authorization](docs/rpc-authentication.md) |
| Use the broker's status call and understand validation, freshness, and quarantine | [RPC session-status query](docs/rpc-session-status-design.md) |
| Review RFC 5880, RFC 7419, and RFC 7880 requirements, test coverage, and limits | [RFC conformance tests](docs/rfc-conformance.md) |
| Build, test, prepare deployment files, or contribute changes | [Contribute to BFD Windows service](CONTRIBUTING.md) |
| Review documentation corrections and validation scope | [Documentation audit](docs/documentation-audit.md) |

For recorded checks and their limits, see the
[validation guide](RUST_SKILLS_VALIDATION.md) and
[dated correctness reviews](CODE_REVIEW.md).

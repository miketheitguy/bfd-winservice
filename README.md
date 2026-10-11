# BFD Windows service

For Windows network administrators, this service monitors one IPv4 or IPv6
peer with Bidirectional Forwarding Detection (BFD). Follow this guide to install
and configure the service. Optional Border Gateway Protocol (BGP)
control starts and stops a configured Windows BGP peer as BFD state changes.

The BFD service runs as LocalService. A separate LocalSystem broker manages BGP
through a local pipe restricted to the BFD service identity.

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

- 64-bit Windows 10 or later, or a corresponding Windows Server release, on an
  x64 processor.
- An x64 MSI from
  [GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases),
  or matching
  `bfd-winservice.exe`, `BFD-Service.man`, and
  `Initialize-Logging.ps1` files supplied by your service maintainer.
- Administrator PowerShell access to create the service and its registry settings.
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

The default transport is single-hop. File output defaults to disabled; its
configured path is `C:\ProgramData\BfdWinService\trace.log`.

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

SCM `Running` confirms engine startup. After configuring the remote peer,
confirm event `102` in `BFD-Service/Operational` to verify BFD reached `Up`.
See [Verify peer communication](docs/setup.md#6-verify-peer-communication)
for the query and expected events.

Non-administrators can query service status and read event/file logs. Start/Stop
and configuration changes require an elevated Administrator; SYSTEM retains
Windows service lifecycle access.

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
| Review RFC 5880, RFC 7419, and RFC 7880 requirements, test coverage, and limits | [RFC conformance tests](docs/rfc-conformance.md) |
| Build, test, prepare deployment files, or contribute changes | [Contribute to BFD Windows service](CONTRIBUTING.md) |

For recorded checks and their limits, see the
[validation guide](RUST_SKILLS_VALIDATION.md) and
[dated correctness reviews](CODE_REVIEW.md).

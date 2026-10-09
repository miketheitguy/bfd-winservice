# BFD Windows service

For Windows network administrators, this service monitors one IPv4 or IPv6
peer with Bidirectional Forwarding Detection (BFD). Follow this guide to install
and configure the service. Optional Border Gateway Protocol (BGP)
control starts and stops a configured Windows BGP peer as BFD state changes.

For probes that establish without a discriminator handshake, configure an
IPv4/IPv6 [Seamless BFD initiator or reflector](docs/seamless.md).

The service uses these Windows names:

| Name | Value |
| --- | --- |
| Windows service | `BfdWinService` |
| Event provider | `BFD-Service` |
| Event Log channel | `BFD-Service/Operational` |

## Before you begin

You need:

- 64-bit Windows 10 or later, or a corresponding Windows Server release, on an
  x64 processor.
- Matching `bfd-winservice.exe`, `BFD-Service.man`, and
  `Initialize-Logging.ps1` files supplied by your service maintainer.
- Administrator PowerShell access to create the service and its registry settings.
- A local IP address, its interface index, and a remote BFD peer that you can
  configure. See [network requirements](docs/protocol.md).

## Quick start

Use **PowerShell as Administrator** for installation and configuration.

### 1. Copy the installation files

Follow [Prepare installation files](docs/setup.md#prepare-installation-files)
to copy the supplied files to `C:\Program Files\BfdWinService` or your chosen
installation folder.

### 2. Configure a fresh installation

Complete steps 1–3 in [Set up a BFD session](docs/setup.md#install-the-windows-service)
to create the service, provision its registry values, and register its Operational log.

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
| Check ports, firewall requirements, and protocol limits | [Network and protocol behavior](docs/protocol.md) |
| Review RFC 5880 requirements, coverage, and implementation limits | [RFC 5880 conformance review](docs/rfc5880-conformance.md) |
| Build, test, prepare deployment files, or contribute changes | [Contribute to BFD Windows service](CONTRIBUTING.md) |

For recorded checks and their limits, see the
[validation guide](RUST_SKILLS_VALIDATION.md) and
[dated correctness reviews](CODE_REVIEW.md).

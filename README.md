# BFD Windows service

For Windows network administrators, this service monitors one IPv4 or IPv6
peer with Bidirectional Forwarding Detection (BFD). Follow this guide to build
and configure a fresh installation. Optional Border Gateway Protocol (BGP)
control starts and stops a configured Windows BGP peer as BFD state changes.

The service uses these Windows names:

| Name | Value |
| --- | --- |
| Windows service | `BfdWinService` |
| Event provider | `BFD-Service` |
| Event Log channel | `BFD-Service/Operational` |

## Before you begin

You need:

- Windows 10 or later, or a corresponding Windows Server release.
- Rust with a `windows-msvc` target.
- Visual Studio's **Desktop development with C++** workload, including the
  Microsoft Visual C++ (MSVC) toolchain and Windows Software Development Kit (SDK).
- Administrator PowerShell access to create the service and its registry settings.
- A local IP address, its interface index, and a remote BFD peer that you can
  configure. See [network requirements](docs/protocol.md).

## Quick start

Run the commands from the repository root.

### 1. Build the executable

Build the service in PowerShell:

```powershell
cargo build --release
```

The build produces `target\release\bfd-winservice.exe`. For SDK tool discovery
and build troubleshooting, see [Build and validate the service](docs/development.md).

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
| Enable file output or interpret Operational events | [Logs and events](docs/logging.md) |
| Connect BFD state changes to a Windows BGP peer | [Control a Windows BGP peer](docs/bgp.md) |
| Check ports, firewall requirements, and protocol limits | [Network and protocol behavior](docs/protocol.md) |
| Build, run tests, or generate Rust API documentation | [Build and validate the service](docs/development.md) |

For recorded checks and their limits, see the
[validation guide](RUST_SKILLS_VALIDATION.md) and
[dated correctness reviews](CODE_REVIEW.md).

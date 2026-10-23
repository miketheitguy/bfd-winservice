# BFD Windows service

## What is BFD?

Bidirectional Forwarding Detection (BFD) uses frequent, lightweight probes to
detect failures in the forwarding path between two systems. It can detect
failures in less than a second, including failures that leave the network
interface up. This lets routing protocols react sooner than their own failure
timers, reducing the time traffic follows an unusable path.

When integrated with Border Gateway Protocol (BGP), BFD can trigger a peer
session shutdown so BGP removes the affected routes and selects an available
alternative. In this anycast DNS example, Server A and Server B advertise the
same address, `203.0.113.53/32`. After Server A becomes unreachable, Router C
redirects Client D's DNS queries to Server B without changing the DNS address:

![Anycast DNS failover: Router C detects Server A's failure with BFD, notifies BGP, and reroutes Client D's queries for 203.0.113.53 to Server B.](docs/images/anycast-dns-bfd-bgp.gif)

## BFD on Windows

Cowabunga, Windows network crew! Let's get your session totally dialed in. This
service runs a Bidirectional Forwarding Detection (BFD) session with one IPv4 or
IPv6 peer, or a stateless Seamless BFD reflector for multiple initiators. Follow
this guide to install and configure the service. Optional Border Gateway
Protocol (BGP) control starts and stops a configured Windows BGP peer as session
state changes.

The packet engine runs as LocalService. A separate LocalSystem broker manages
the configured BGP peer through authenticated local RPC. For the process and
trust boundaries, see [Service communication](docs/service-communication.md).

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

Turtle power starts with the right gear, dude. Before you paddle out, get this
setup together:

- 64-bit Windows 10 or later, or Windows Server 2016 or later, on an
  x64 processor.
- The x64 offline setup bundle (`BfdWinService-VERSION-x64-setup.exe`) from
  [GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases).
- Administrator PowerShell access to install the service and configure registry
  settings.
- A local IP address, its interface index, and a remote BFD peer that you can
  configure. See [network requirements](docs/protocol.md).

## Quick start

Get the installation lined up before the pizza break, crew. Use
**PowerShell as Administrator** for installation and configuration.

### 1. Install the service

Kick shell with the package, dude. Follow
[Install with the offline setup
bundle](docs/setup.md#install-with-the-offline-setup-bundle)
to install Microsoft's native x64 Visual C++ runtime and the service.
The bundle installs the files and Automatic (Delayed Start) services,
registers the Operational provider, and
creates firewall rules. The service remains stopped for configuration.

### 2. Configure a fresh installation

Give these settings the Donatello treatment: check the details. Follow
[Configure the session](docs/setup.md#2-configure-the-session) to provision the
required registry values.

The default transport is single-hop. See [logging](docs/logging.md) to enable
optional file output.

### 3. Start the service

Time to get this bodacious session rolling. In **PowerShell as Administrator**,
start the configured service:

```powershell
Start-Service BfdWinService
```

The command returns without output on success.

## Verify the session

Cowabunga comes with evidence, ninja crew. Check the Windows Service Control
Manager (SCM) status:

```powershell
Get-Service BfdWinService | Select-Object Name, Status
```

A successful startup reports:

```text
Name          Status
----          ------
BfdWinService Running
```

Sweet, the process started. The startup vibe check still has two parts: SCM
`Running` confirms engine startup. For a classical session or S-BFD initiator,
configure the remote peer and confirm event `102` in `BFD-Service/Operational`
to verify BFD reached `Up`. A stateless reflector has no per-peer `Up` state;
verify replies from an initiator instead. See
[Verify peer communication](docs/setup.md#6-verify-peer-communication) for the
query and expected events.

Use Windows lifecycle queries and event logs for monitoring. See
[Monitor service status and BFD events](docs/monitoring.md).

Non-administrators can query service status. Log reads depend on the host's
Event Log and filesystem permissions. Start/Stop and configuration changes
require an elevated Administrator; SYSTEM retains Windows service lifecycle
access.

With BGP control enabled, initial BFD negotiation leaves BGP unchanged. After
BFD reaches `Up`, a path failure can stop the configured peer. Administrative
disablement at either end releases a Stop previously issued by BFD; it does not
stop BGP. Dude, read the [BGP action rules](docs/bgp.md) before connecting a
production peer.

BFD runs only as the installed Windows service and accepts no command-line
arguments. Read its version from Windows file properties or PowerShell:

```powershell
(Get-Item 'C:\Program Files\BfdWinService\bfd-winservice.exe').VersionInfo |
    Select-Object FileVersion, ProductVersion
```

## Documentation

Pick your next mission, turtle crew. The [documentation index](docs/README.md)
links operator guides, architecture references, and development procedures:

| Task | Guide |
| --- | --- |
| Install, configure, verify, or stop a session | [Set up a BFD session](docs/setup.md) |
| Look up registry values, defaults, and authentication | [Registry configuration reference](docs/configuration.md) |
| Set or update the encrypted authentication key | [Authentication key administration](docs/configuration.md#authentication-key-administration) |
| Configure an S-BFD initiator, reflector, or anycast target | [Configure Seamless BFD](docs/seamless.md) |
| Connect BFD state changes to a Windows BGP peer | [Control a Windows BGP peer](docs/bgp.md) |
| Query service status and read BFD state events | [Monitor service status and BFD events](docs/monitoring.md) |
| Understand authentication, privilege boundaries, and compiler/linker protections | [Security, authentication, and build hardening](docs/security.md) |
| Build, test, prepare deployment files, or contribute changes | [Contribute to BFD Windows service](CONTRIBUTING.md) |

For validation scope and review checks, see the
[validation guide](RUST_SKILLS_VALIDATION.md) and
[code review checklist](CODE_REVIEW.md).

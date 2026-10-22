# Migrate foreground deployments to Windows services

Windows administrators, use this guide to replace an older foreground BFD
deployment with the installed service. BFD accepts no command-line arguments;
`--console`, `--help`, and `--version` have been removed. Ctrl+C no longer
controls BFD. Use Windows Service Control Manager (SCM) commands and event logs.

## Revision scope

Service-only execution is introduced in [v4.0.0](releases/4.0.0.md). Versions
through v3.0.2 support foreground execution and runtime privilege reduction.
Upgrade both services together using `BfdWinService-4.0.0-x64-setup.exe` when
applying this migration. The CLI and Rust API removals make this a major
release under the [version policy](../CONTRIBUTING.md#choose-a-release-version).
The [dated validation record](service-only-validation-2026-10-22.md) identifies
the private package used before release version stamping.

Both services keep their installed accounts and SID types. SCM supplies only
enabled `SeChangeNotifyPrivilege`; each daemon validates that exact set without
adjusting its token. For the rejection and repair behavior, see
[service isolation](security/service-isolation.md#bfd-privilege-allowlist).

<a id="prepare-installation-files"></a>

## Install the service

1. Stop the older foreground process and disable any scheduled task or wrapper
   that launches it. Confirm it has released the configured BFD addresses/ports.
2. Record the existing protected registry configuration and authentication keys
   using your normal secure backup procedure. Keep key material out of logs.
3. Follow [Install with the offline setup bundle](setup.md#install-with-the-offline-setup-bundle).
   Loose executables alone do not provision accounts, service SIDs, privilege
   allowlists, ACLs, firewall rules, or the logging provider.
4. Review the existing values against the [configuration reference](configuration.md).
   [Enable optional file output](logging.md#configure-file-logging) if you
   previously redirected STDOUT. The BFD service SID needs Modify access to a
   custom log directory, including rights for rotation; an account-only
   LocalService grant is insufficient for restricted writes.

<a id="start-and-verify-the-console-session"></a>

## Start and verify the service

Start the configured service in **PowerShell as Administrator**:

```powershell
Start-Service BfdWinService
Get-Service BfdWinService | Select-Object Name, Status
```

Confirm `Running`, then [verify peer communication](setup.md#6-verify-peer-communication).
Use [Logs and events](logging.md) for ETW and optional file output.
Startup rejects an unexpected service token before opening configured resources.
Use setup repair to restore the installed policy before restarting.

Read the version without executing the daemon:

```powershell
(Get-Item 'C:\Program Files\BfdWinService\bfd-winservice.exe').VersionInfo |
    Select-Object FileVersion, ProductVersion
```

To stop BFD and complete its administrative shutdown, run:

```powershell
Stop-Service BfdWinService
```

## Migrate library callers

Remove `CommandLine`, `Options::console`, and `runtime::drop_privileges` usage.
Call `config::load_registry()`, `Logger::new()`, and `Logger::open(&options)`
without a mode parameter. The executable's foreground runner and Ctrl+C handler
are removed. Library users can still drive `Engine::run_until` with a
`StopSignal`; installed-service identity and privilege checks are separate from
portable protocol APIs. See [library development](development/library.md).

The broker also rejects public help/version options. Its fixed private MSI
transaction commands remain installer implementation details; use setup bundle
installation or repair rather than invoking those commands manually.

# Remove a legacy manual installation

Turtle crew, use this only for an older installation created manually rather
than by MSI or the setup bundle. For a packaged installation, use
[bundle removal](../setup.md#remove-a-setup-bundle-installation). Run the
commands in one elevated PowerShell window.

## 1. Stop the service

Finish service cleanup before removing its registration:

```powershell
Stop-Service BfdWinService
Stop-Service BfdBgpBroker -ErrorAction SilentlyContinue
```

Confirm `Get-Service BfdWinService` reports `Stopped` before continuing.

## 2. Unregister the manifest

Remove the provider's manifest registration:

```powershell
$installDirectory = 'C:\Program Files\BfdWinService'
$manifest = (Resolve-Path (Join-Path $installDirectory 'BFD-Service.man')).Path
wevtutil.exe um $manifest
if ($LASTEXITCODE -ne 0) {
    throw 'BFD-Service manifest removal failed'
}
```

A successful command returns without output. For registration and removal syntax,
see Microsoft's [wevtutil commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

## 3. Delete the service

Remove the stopped service from SCM:

```powershell
sc.exe delete BfdWinService
if (Get-Service BfdBgpBroker -ErrorAction SilentlyContinue) {
    sc.exe delete BfdBgpBroker
}
```

The command reports successful deletion. After SCM completes deletion,
`Get-Service BfdWinService` no longer finds the service.

For another fresh installation, return to [Install with the offline setup bundle](../setup.md#install-with-the-offline-setup-bundle).

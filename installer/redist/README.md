# Microsoft Visual C++ Redistributable (x64)

This directory contains Microsoft's unmodified native installer for the x64
Visual C++ v14 runtime used by BFD Windows Service.

- File: `VC_redist.x64.exe`
- File and product version: `14.51.36247.0`
- Downloaded: `2026-10-22` (UTC)
- Download URL: <https://aka.ms/vc14/vc_redist.x64.exe>
- Resolved binary URL:
  <https://download.visualstudio.microsoft.com/download/pr/ebdab8e5-1d7b-4d9f-a11b-cbb1720c3b12/843068991DAAA1F73AD9F6239BCE4D0F6A07A51F18C37EA2A867E9BECA71295C/VC_redist.x64.exe>
- SHA-256: `843068991daaa1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c`

`VC_redist.x64.json` records the download provenance, size, version, and
Microsoft signing certificate. `VC_redist.x64.exe.sha256` records the checksum.
The installer retains Microsoft's embedded signature and license terms.
Read the [Microsoft runtime license terms](https://aka.ms/VCRedistLicense).

`scripts/Build-Bundle.ps1` embeds this exact file in
`BfdWinService-VERSION-x64-setup.exe`, followed by the matching BFD MSI.
The bundle installs the runtime with Microsoft's native installer before
installing BFD. It skips an equal or newer installed x64 runtime and retains
the shared runtime when BFD is removed. Both payloads are embedded, so no
download is required on the target computer. The setup bundle is the sole
distributable installer; the BFD MSI exists only as its internal payload. See
[installation instructions](../../docs/setup.md#install-with-the-offline-setup-bundle).

From the repository root in PowerShell, verify the vendored file:

```powershell
.\scripts\Test-VcRedist.ps1
```

The check requires a valid Microsoft Authenticode signature and matching
version, size, and SHA-256 metadata. It reports the validated version and hash.

To update the pinned runtime, download the x64 installer from the download URL,
verify its Microsoft signature, and update both metadata files together with
the binary. Confirm the version through the downloaded file's properties;
Microsoft updates the download URL's contents as versions are released.

See Microsoft's [latest supported redistributable downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
and [deployment guidance](https://learn.microsoft.com/en-us/cpp/windows/choosing-a-deployment-method)
for package selection and installing the native prerequisite before an
application's MSI.

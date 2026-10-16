# MSVC C and MIDL build profile

This baseline targets Windows x64 and a current compatible MSVC/Windows SDK. Verify support for all flags; report unsupported controls instead of silently removing them.

## Compiler

Compile every maintained and generated C unit with:

```text
cl.exe /nologo /c /TC /MD /GS /guard:cf /guard:ehcont /sdl /W4 /WX /D_WIN32_WINNT=0x0602 /I <generated-headers> /I <source-headers> <source.c>
```

Add `/analyze /analyze:external-` for maintained C. Analyze project code while excluding external headers from that pass. Keep generated MIDL code under `/W4 /WX` and robust stub generation; do not add blanket warning suppressions to make generated and maintained code share an inappropriate analysis policy.

| Option | Purpose and scope |
| --- | --- |
| `/nologo /c` | Reproducible quiet compilation to object files; not mitigations. |
| `/TC` | Explicit C language mode, including generated `.c` stubs. |
| `/MD` | Consistent dynamic CRT; preserve allocation ownership across boundaries. |
| `/GS` | Native stack-buffer security checks; not a proof against all corruption. |
| `/guard:cf` | CFG instrumentation and targets; final linker needs `/GUARD:CF`. |
| `/guard:ehcont` | EH continuation metadata; final linker needs `/GUARD:EHCONT`. |
| `/sdl` | Additional MSVC security diagnostics/checks. |
| `/W4 /WX` | Strict warnings; warnings are build failures. |
| `/analyze /analyze:external-` | Static analysis of maintained C; fix diagnosed contract violations. |
| `/D_WIN32_WINNT=0x0602` | Windows API declaration floor used by the V5 RPC policy; not a claim that the complete application supports every Windows 8 system. |

Remove ambient `CL` and `_CL_` from the **compiler subprocess** so options cannot override language mode or disable checks. Inspect response files, toolchain wrappers, and effective arguments too. Apply only necessary compiler setup values such as PATH, INCLUDE, LIB, and LIBPATH from a trusted selected Visual Studio installation; do not print a captured full environment or mutate the parent process environment unnecessarily.

C SEH does not require `/EHsc`. This baseline does not pass `/EHa`, `/Zi`, `/ZH:SHA_256`, or a native AddressSanitizer option. Do not claim native debug checksums or native sanitizer coverage merely because another language's build enables them.

## MIDL and archive

Generate separate client and server stubs with:

```text
midl.exe /nologo /env x64 /robust /Oicf /app_config /prefix client <client-prefix> server <server-prefix> /client stub /server none /h <client-header.h> /out <output-directory> /acf <client.acf> <contract.idl>
midl.exe /nologo /env x64 /robust /Oicf /app_config /prefix client <client-prefix> server <server-prefix> /server stub /client none /h <server-header.h> /out <output-directory> <contract.idl>
lib.exe /nologo /OUT:<bridge.lib> <generated-and-maintained-objects>
```

`/acf` selects the client asynchronous procedures. `/robust` and IDL `[range]` constraints validate supported NDR contracts; also validate application semantics after unmarshaling. Use fixed-width bounded records, explicit bindings, separate symbol prefixes, and no caller-selected privileged targets. Link the resulting archive and `Rpcrt4.lib` into the final image. The archive operation itself does not establish executable mitigations.

## Final x64 image linker

Require these on the final executable/DLL link, even when a different build system owns that step:

```text
/MACHINE:X64 /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF /GUARD:EHCONT /CETCOMPAT /LARGEADDRESSAWARE
```

ASLR needs relocations; high-entropy ASLR also needs large-address support. Compiler CFG checks and linker CFG metadata are both necessary. An enabled empty EH continuation table can be valid if there are no continuation targets. CET compatibility is a declaration; actual enforcement depends on Windows, hardware, and process mitigation policy. `/SAFESEH` is x86-only. SEHOP is a separate Windows process policy.

For the symbol-free production profile, `/DEBUG:NONE` suppresses linker PDB output; keep development/test diagnostics. Symbol stripping is not executable signing, authentication, or a memory-safety mitigation. Verify final PE architecture, relocations, DLL characteristics, CFG tables, cookie metadata, EH continuation data, CET bit, and debug policy with `dumpbin /headers /loadconfig` or an equivalent parser. Do not assert per-function coverage from metadata alone.

## Primary references

- [MSVC C/C++ compiler options](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-options-listed-alphabetically?view=msvc-170)
- [CL environment options](https://learn.microsoft.com/en-us/cpp/build/reference/cl-environment-variables?view=msvc-170)
- [MSVC code analysis](https://learn.microsoft.com/en-us/cpp/build/reference/analyze-code-analysis?view=msvc-170)
- [MIDL robust generation](https://learn.microsoft.com/en-us/windows/win32/midl/-robust)
- [Microsoft linker options](https://learn.microsoft.com/en-us/cpp/build/reference/linker-options?view=msvc-170)

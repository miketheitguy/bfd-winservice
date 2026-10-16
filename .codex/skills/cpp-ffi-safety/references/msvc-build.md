# MSVC C++ build profile

Use this Windows x64 policy for actual C++ translation units and dependencies. It is the prospective C++ counterpart of the native C baseline; bfd-winservice's bridge itself consists of C translation units.

```text
cl.exe /nologo /c /TP /EHsc /MD /GS /guard:cf /guard:ehcont /sdl /W4 /WX /D_WIN32_WINNT=0x0602 <source.cpp>
```

- `/TP` explicitly selects C++; `/EHsc` enables standard synchronous C++ exception handling and stack unwinding inside C++. It does not permit exceptions through FFI.
- `/MD` selects a consistent dynamic CRT. Keep allocation/deallocation on the owning side of the ABI.
- `/GS`, `/guard:cf`, `/guard:ehcont`, and `/sdl` provide native buffer checks, CFG instrumentation, EH continuation metadata, and additional security checks.
- `/W4 /WX` make warnings fail the build. Add `/analyze /analyze:external-` for maintained C++ and resolve findings. Evaluate third-party diagnostics deliberately instead of disabling warnings globally.
- `/D_WIN32_WINNT=0x0602` is the local RPC API declaration baseline, not a universal product support promise. Select and document the real supported Windows floor when reusing this elsewhere.
- `/nologo /c` are output/compilation mechanics, not mitigations.

Remove `CL` and `_CL_` from the compiler subprocess. Review wrappers, response files, dependency build options, and effective invocations for conflicting options. Do not mix `/EHa` and `/EHsc` policies or use `/EHa` to recover from memory corruption. Merely rebuilding a dependency with `/EHsc` does not make its public interface exception-safe; a catching C++ wrapper remains mandatory.

Require the final x64 MSVC link to retain:

```text
/MACHINE:X64 /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF /GUARD:EHCONT /CETCOMPAT /LARGEADDRESSAWARE
```

These select x64, ASLR, high-entropy address space, DEP compatibility, CFG/EH metadata, CET compatibility, and large-address support. Pair CFG/EH link options with compiler instrumentation. Keep relocations for ASLR. Verify final PE flags/tables, cookie metadata, and profile-specific debug output. An enabled empty EH continuation table can be legitimate. Image metadata does not prove per-function instrumentation or active hardware enforcement.

For a symbol-free production profile, add `/DEBUG:NONE`; keep debug information for development and diagnostics. Native `/Zi`, `/ZH:SHA_256`, or AddressSanitizer would be separate intentional additions and must not be claimed from another language's settings. `/SAFESEH` is x86-only; SEHOP requires a separate Windows process policy. CET enforcement depends on Windows and hardware.

Use a compatible pinned/controlled MSVC and Windows SDK toolchain. Do not remove unsupported flags silently or overwrite a dependency's exception model without reviewing its requirements and ABI. Link the selected CRT and required system libraries through the normal toolchain driver.

## Primary references

- [MSVC compiler options](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-options-listed-alphabetically?view=msvc-170)
- [MSVC exception model](https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model?view=msvc-170)
- [MSVC linker options](https://learn.microsoft.com/en-us/cpp/build/reference/linker-options?view=msvc-170)

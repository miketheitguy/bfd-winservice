---
name: cpp-ffi-safety
description: Harden C++ dependencies and C ABI wrappers, especially when called from Rust. Use for MSVC /EHsc builds, C++ exception-to-status translation, noexcept exports, allocator ownership, and FFI review. Applies only when C++ is actually compiled; it does not turn C SEH into C++ exception handling.
---

# C++ FFI exception safety

Inventory translation units and dependencies first. Do not claim a project has C++ merely because MSVC C++ Build Tools are installed. Keep C++ compilation separate from C compilation. Read [the MSVC profile](references/msvc-build.md) when editing builds.

## Contain every C++ exception

No C++ exception may cross this FFI boundary. Put a `try`/`catch` boundary entirely inside each exported C++ wrapper, catch all C++ exceptions, and return fixed integer error codes. Use `noexcept` as an additional declaration of the contract, never as a substitute for translation: an escaping exception in a `noexcept` function terminates the process.

```cpp
#include <cstdint>
#include <new>

enum : std::int32_t { FFI_OK = 0, FFI_INVALID = 1,
                     FFI_NO_MEMORY = 2, FFI_INTERNAL = 3 };

// operate() is internal C++ and may throw. All such calls stay inside try.
void operate();

extern "C" std::int32_t ffi_operate() noexcept
{
    try {
        operate();
        return FFI_OK;
    } catch (const std::bad_alloc&) {
        return FFI_NO_MEMORY;
    } catch (...) {
        return FFI_INTERNAL;
    }
}
```

Use an ABI-compatible C header in the real implementation. Map errors into the documented public status contract; avoid leaking exception strings or implementation details. If outputs exist, initialize them and define their validity for failure statuses. Include construction, conversion, callbacks, destruction, and error reporting in the exception-safety audit. A catch handler must not allocate, invoke throwing logging/formatting, or call a throwing destructor. Cleanup itself must satisfy its no-throw contract.

For callbacks into the foreign language, require its own non-unwinding contract and status-based error return. Never rely on `catch (...)` to catch a foreign panic. Do not enable cross-language unwind ABIs as a workaround.

## Enforce native ownership

Expose opaque handles or fixed-layout C-compatible values. Preserve exact calling convention, width, alignment, lifetime, and output validity. Avoid STL objects, C++ references, native exceptions, or compiler-dependent classes across a C ABI. Pair creation/destruction on the side that owns the allocator and CRT. Borrowed memory must outlive every call and asynchronous callback that can access it.

Use RAII internally, checked sizes/conversions, bounded work, strict warnings, and static analysis. Audit `noexcept` destructors and moved/partially constructed objects. Do not use `/EHa` to convert access violations or stack corruption into ordinary recoverable errors. Do not add blanket native SEH around foreign-language frames.

## Verify

Build with `/TP /EHsc` and the complete compiler/linker profile. Test successful calls, a representative typed exception, an unknown C++ exception, and allocation failure translation where practical. Use isolated fixtures and assert integer statuses/output validity. Verify that no exception leaves the wrapper, no handler throws, no allocation crosses the wrong deallocator, and production PE mitigations are present. Scope sanitizer claims to actually instrumented C++ objects.

## Primary references

- [MSVC exception handling models](https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model?view=msvc-170)
- [C++ noexcept](https://learn.microsoft.com/en-us/cpp/cpp/noexcept-cpp?view=msvc-170)
- [Foreign-language unwinding constraints](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding)

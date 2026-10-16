---
name: c-security-hardening
description: Write and review native C with MSVC, bounded Windows RPC bridges, SAL contracts, resource ownership, and narrowly scoped structured exception handling. Use for C compiler/linker hardening and MIDL stubs. Does not prescribe C++ exception handling or Rust implementation rules.
---

# Native C security hardening

Read [the compiler and linker profile](references/msvc-build.md) for native builds and [the RPC lifetime policy](references/rpc-lifetimes.md) for asynchronous RPC wrappers. Keep native code small and limited to APIs that need a native boundary.

## Enforce the C contract

- Compile C translation units explicitly as C. Match SDK calling conventions, declarations, integer widths, structure layouts, and SAL annotations. Use the generated MIDL header as the contract; do not maintain a conflicting handwritten prototype.
- Initialize every structure, output, async state, and handle before use. Define which outputs are valid for each returned status; callers must discard outputs on failure unless the API explicitly defines them.
- Check lengths before addition, multiplication, allocation, copying, or casting. Bound dynamic allocations. Check signed-to-unsigned and narrowing conversions. Validate buffers, count-dependent structures, pointer containment, alignment, and SIDs before dereferencing them.
- Keep allocator pairs exact: MIDL allocation/free, LocalAlloc/LocalFree, RPC context release, event handles, and binding operations each have their own contracts. Never free memory across incompatible allocators or CRT ownership rules.
- Use a single clear cleanup path where it makes ownership auditable. Track partially initialized resources and completed operations explicitly. Check API-specific status values; do not substitute `GetLastError` for an RPC/HRESULT return contract.
- Preserve SDK SAL declarations. For a definition with an annotated prior declaration, use `_Use_decl_annotations_` as appropriate rather than weakening the contract or suppressing analyzer warnings.
- Avoid hidden global ownership, unbounded retry loops, blocking the packet path, secrets in diagnostics, and printing a full process environment when a compiler command fails.

## Use narrow Windows SEH when required

For generated RPC client calls that raise RPC exceptions, centralize the filter in a maintained C header and delegate classification to the SDK:

```c
#include <rpc.h>

static __inline int rpc_exception_filter(unsigned long code)
{
    return RpcExceptionFilter(code);
}
```

Call this policy from `RpcExcept(rpc_exception_filter(RpcExceptionCode()))` around the native RPC invocation that requires it. Preserve the exact exception status for conversion into the documented integer result. Cleanup must still obey the native call's ownership state.

Do not use `EXCEPTION_EXECUTE_HANDLER` for every exception or claim that arbitrary native faults are safe to recover from. Access violations, stack corruption/overflow, illegal instructions, and other fatal classes must follow the SDK filter rather than becoming ordinary transport failures. Do not install catch-all SEH around foreign callbacks or server managers. This filter is not a foreign-language exception or panic translator.

Keep raised-exception tests in a separate test-only object/entry point. Test recoverable RPC statuses through the real filter; classify fatal codes without deliberately corrupting the process. Verify test-only exception injection is not linked into production.

## Verify before reporting success

Compile maintained C with the full warning/analyzer policy and fix findings rather than suppressing broad categories. Generated MIDL C retains `/robust` plus strict compiler warnings. Test changed malformed-input and cancellation paths, and inspect the final executable's mitigation metadata. Distinguish compiler configuration, emitted instrumentation, and mitigation enforcement by Windows.

Do not apply C++ flags to C to silence build failures. Route C++ units to their own exception-safe compilation and FFI wrapper policy. Keep C functions at the FFI boundary status-based, with no assumption that this C filter makes foreign unwinding safe.

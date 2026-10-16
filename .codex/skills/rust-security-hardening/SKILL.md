---
name: rust-security-hardening
description: Harden and review Rust code, unsafe Windows API boundaries, Rust FFI exports, and Windows MSVC Rust builds. Use for Rust security reviews, panic containment, native buffer ownership, Cargo hardening, and sanitizer coverage. Covers Rust only; use language-specific skills for C or C++ implementations.
---

# Rust security hardening

Apply this skill to Rust source and Rust build configuration. Read [the build profile](references/build-profile.md) when changing compiler, linker, profile, or sanitizer settings. The bundled TOML assets reproduce the Windows x64 baseline; merge their settings into an existing project instead of replacing its manifest.

## Establish the boundary

Read applicable repository instructions, existing Rust guidelines, the target/toolchain, and the actual FFI declarations. Preserve stricter existing rules. Identify untrusted inputs, privileged operations, borrowed native resources, cancellation paths, and the process panic strategy before changing them. Windows MSVC settings apply to that platform; do not impose them on unrelated Rust targets.

## Enforce Rust invariants

- Prefer safe Rust and typed states. Deny unsafe code by default; allow it only in narrow reviewed Windows/FFI modules. Explain each unsafe operation's actual preconditions, initialization, alignment, bounds, ownership, and lifetime. Keep `unsafe_op_in_unsafe_fn` denied.
- Preserve ownership and borrowing. Never extend a lifetime, invent a mutable alias, transmute a wire representation into an unchecked enum, or add `Send`/`Sync` without a proof covering the native API and concurrent destruction.
- Use `#[repr(C)]` for shared records and the exact ABI/calling convention, integer widths, layout, and pointer mutability required by the native contract. Check important sizes and offsets. Avoid Rust-layout enums, `String`, `Vec`, references, or trait objects in wire/ABI records.
- Treat native output as untrusted. Initialize storage; use an aligned allocation for structures, not a `Vec<u8>` cast to a more aligned type. Validate returned lengths, overflow, counts, pointer ranges, alignment, and SID boundaries before dereferencing or calling SID comparison APIs.
- Convert wire data once into validated Rust types with fallible conversion. Reject invalid discriminants, Boolean encodings, address lengths, nonzero IDs, time values, and inconsistent optional fields. Use checked arithmetic for externally supplied sizes and times. Do not clamp malformed security data into validity.
- Wrap owned handles and allocations in small RAII types with the correct matching release function. Separate borrowed handles from owned handles. Review partial initialization and every early return for leaks and double release.
- Bound queues, allocations, active operations, retries, logging, and shutdown waits. Use a supervised blocking worker for synchronous native work. Do not hold a packet-processing lock while calling a provider, awaiting RPC, or performing blocking I/O.
- Model unavailable or timed-out telemetry explicitly. Clear stale cached data after rejected replies. A transport error must not become a fabricated healthy/unhealthy peer state or an automatic privileged action.
- Avoid production `unwrap`/`expect` on fallible input paths. Propagate typed errors; redact keys, credentials, environment dumps, and sensitive buffers from diagnostics. Use a reviewed constant-time comparison for secret authentication values where applicable.

## Contain panics on the Rust side

Use non-unwinding `extern "C"` or the required non-unwinding `extern "system"` ABI at this boundary. Never change it to `C-unwind`/`system-unwind` to accommodate a dependency. Never let a Rust panic unwind into native code, and never attempt to catch a foreign exception in Rust.

Production release uses `panic = "abort"`. This prevents panic unwinding but terminates the process without normal destructor or service-stop cleanup; use `Result` for recoverable failures. A panic attempting to leave a non-unwinding Rust ABI also aborts under an unwind-enabled build. Do not misreport this fail-stop behavior as graceful error translation.

If recoverable panic translation is required under `panic = "unwind"`, put `catch_unwind` entirely inside the Rust export and convert the result into a defined integer status before returning. Audit captured state and the handling/dropping of the panic payload; do not add blanket `AssertUnwindSafe` to bypass that audit. `catch_unwind` cannot catch aborting panics and is not a foreign-exception handler.

## Preserve native ownership across cancellation

Dropping a future or reaching a deadline does not end a native call. Keep all Rust-owned output buffers, security descriptors, SIDs, bindings, events, and callback state alive until the native operation is conclusively complete and no callback can recur. Drain/unregister callbacks before releasing their state. Avoid `TerminateThread` and unbounded replacement workers.

For uncertain native ownership, use the documented fail-closed policy: retain one bounded worker and its allocations, or terminate the process when that process's safety model requires it. Do not return from an active native stack or free buffers merely to meet a timeout. If editing a C bridge or local RPC contract, also use `$c-security-hardening` or `$windows-rpc-authentication` when available. In every case, prove completion from the native API's documented state machine before Rust releases its resources; an unknown completion state is insufficient.

## Verify the result

Review the effective build commands, not just checked-in flag names. Run focused tests of changed validation, ownership, cancellation, and recovery behavior; run configured strict Clippy checks. Verify the final production PE separately from unwind-enabled tests. Report ASan's actual instrumentation scope and any ignored or unavailable installed-service checks. Never claim a successful fixture proves the real SCM-issued token configuration.

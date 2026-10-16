# Windows x64 Rust build profile

Use the complete [Cargo configuration](../assets/cargo-config.toml), [profile and lint settings](../assets/cargo-profiles.toml), and [toolchain pin](../assets/rust-toolchain.toml) as the tested baseline extracted from bfd-winservice. Select an explicitly pinned compatible toolchain when reusing it elsewhere. These files are merge inputs, not commands to replace existing project files.

## Compiler settings

| Setting | Required behavior |
| --- | --- |
| Explicit `x86_64-pc-windows-msvc` build target | Applies target settings to the target graph, keeping host build scripts/procedural macros separate. |
| `-C control-flow-guard=yes` | Emits indirect-call checks and valid-target metadata; pair with `/GUARD:CF`. |
| `-C relocation-model=pic` | Supports relocation; pair with image ASLR flags. |
| `-Z stack-protector=all` | Requests stack protector instrumentation throughout compiled functions; do not confuse with a C compiler option. |
| `-Z ehcont-guard=yes` | Emits exception continuation metadata; pair with `/GUARD:EHCONT`. |
| `-Z src-hash-algorithm=sha256` | SHA-256 source checksums when debug data is emitted; not signing or authentication. |
| `overflow-checks = true` in dev and release | Checks ordinary integer overflow; explicit checked/wrapping/saturating operations retain their semantics. |
| Release `panic = "abort"` | No production panic unwinding; process termination skips normal cleanup. |
| Release `opt-level = 3` | Production optimization policy, not an access control. |
| Dev `debug = 2`; release `debug = 0`, `strip = "symbols"` | Retain development diagnostics; omit distributed release symbols. |

Pin nightly Rust with `rust-src`, `clippy`, and `rustfmt`. The `-Z` flags, Cargo `profile-rustflags`, and `build-std` need the corresponding nightly capabilities. Do not silently drop them to make a stable build succeed. Revalidate intentional toolchain or policy changes against supported platforms.

`[unstable] build-std = ["std", "panic_unwind"]` rebuilds the target standard library with the target flags. `profile-rustflags = true` permits release-only linker settings. This covers compiled Rust dependencies and rebuilt Rust standard-library code, not Windows DLLs or separately compiled native libraries.

## Final MSVC linker settings

Pass each option as a separate `-C link-arg=...` pair:

| Option | Purpose |
| --- | --- |
| `/MACHINE:X64` | Explicit x64 architecture. |
| `/DYNAMICBASE` | ASLR-compatible image. |
| `/HIGHENTROPYVA` | High-entropy 64-bit ASLR; requires ASLR and large-address support. |
| `/LARGEADDRESSAWARE` | Address space above 2 GB; supports high-entropy ASLR. |
| `/NXCOMPAT` | DEP/NX compatibility. |
| `/GUARD:CF` | CFG load-configuration metadata; compiler instrumentation is also required. |
| `/GUARD:EHCONT` | Exception continuation metadata; an enabled empty table can be valid. |
| `/CETCOMPAT` | CET shadow-stack compatibility declaration. |
| `/DEBUG:NONE` in release only | Suppresses linker-generated PDB/debug output; retain dev/ASan PDBs. |

Do not infer runtime CET enforcement from the image bit; Windows, hardware, and process policy also matter. SEHOP is a separate Windows process policy. `/SAFESEH` is for x86 and must not be added to this x64 profile.

## Lints and test profiles

Keep `warnings = deny` (with lower priority for the group), `unsafe_code = deny`, `unsafe_op_in_unsafe_fn = deny`, `clippy::unwrap_used = deny`, and `clippy::undocumented_unsafe_blocks = deny`. Narrow, justified unsafe boundaries are permitted; disabling the lint across the crate is not a substitute for review. Ensure workspace members actually inherit workspace lints when porting the fragment.

The bundled `test-release` alias uses `--locked --release --config 'profile.release.panic="unwind"'` solely to run the test graph. Rebuild ordinary production release afterward to verify its abort strategy and symbol policy.

The `asan` profile inherits dev and uses `panic = "unwind"`. Its alias uses `--locked --profile asan --target-dir target/asan`, adds `-Z sanitizer=address` through the target `rustflags`, and sets matching target `rustdocflags` for documentation tests. Preserve the other target flags: Cargo target settings take precedence over `build.rustflags`, and command-line configuration arrays merge with file arrays. Check the actual invocation for precedence conflicts, including `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, target-specific environment overrides, and duplicate options.

Rust ASan covers instrumented Rust and the rebuilt standard library. It does not instrument the existing C bridge or system DLLs. Use the matching toolchain's sanitizer runtime when running tests; do not hardcode a developer's Visual Studio version or add an untrusted directory to PATH. Native ASan requires its own deliberate compatible build and test policy.

## Verification evidence

Inspect final PE architecture, relocations, ASLR/NX/large-address flags, CFG flags and tables, security-cookie metadata, EH continuation metadata, CET compatibility, and profile-specific debug output. Use `dumpbin /headers /loadconfig` or a reviewed PE parser. A security-cookie address does not prove every function was instrumented. Recheck after toolchain changes or flag overrides; do not report configuration intent as observed artifact evidence.

## Primary references

- [Rust code generation options](https://doc.rust-lang.org/rustc/codegen-options/index.html)
- [Rust stack protector](https://doc.rust-lang.org/unstable-book/compiler-flags/stack-protector.html)
- [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [Cargo unstable features](https://doc.rust-lang.org/cargo/reference/unstable.html)
- [Rust FFI and unwinding](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding)
- [Microsoft linker options](https://learn.microsoft.com/en-us/cpp/build/reference/linker-options?view=msvc-170)

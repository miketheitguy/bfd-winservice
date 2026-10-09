# Rust Security Hardening Guide: Windows Server 2019+

This guide details how to configure production-ready binary hardening for Rust applications targeting **Windows Server 2019 and newer**. It utilizes stable codegen flags, nightly sanitizers, and strict **Microsoft Visual Studio (MSVC)** linker parameters to protect binaries against exploit primitives like memory corruption and control-flow hijacking.

---

## 1. Stable Hardening Flags (`-C`)

Stable codegen options change how `rustc` transforms code into machine instructions. These are production-ready and work out-of-the-box on the stable compiler.

* **`overflow-checks = true`**  
  Forces runtime panics on integer overflows. This prevents logic flaws and integer wrapping vulnerabilities in production binaries.
* **`panic = "abort"`**  
  Strips complex stack unwinding metadata (`.eh_frame` equivalents). This minimizes the active attack surface available during an active crash or panic condition.
* **`-C control-flow-guard`**  
  Enables Windows Control Flow Guard (CFG). This injects runtime checks to validate indirect call targets, preventing attackers from hijacking function pointers.

---

## 2. Windows Server 2019+ Linker Directives (MSVC)

These arguments are passed directly to the MSVC linker (`link.exe`) to configure core operating system security integrations. These features are fully mature and enforced natively by the Windows Server 2019 / 2022 kernel.

* **`/NXCOMPAT`**  
  Enables Data Execution Prevention (DEP). Marks memory regions (like the stack and heap) as non-executable, preventing raw shellcode execution.
* **`/DYNAMICBASE`**  
  Enables Address Space Layout Randomization (ASLR). Randomizes the location of program components in memory at boot.
* **`/HIGHENTROPYVA`**  
  Enables 64-bit High-Entropy ASLR. Significantly expands the memory randomization pool on 64-bit kernels, making address-guessing attacks mathematically unfeasible.
* **`/GUARD:CF`**  
  Coordinates the linker with the compiler's Control Flow Guard bitmap. Ensures all linked libraries and object files adhere to the valid execution path map.
* **`/CETCOMPAT`**  
  Enables Intel/AMD Hardware-enforced Stack Protection (Shadow Stacks). Windows Server 2019+ natively reads this header marker. On supported hardware (Intel 11th Gen+, AMD Zen 3+), it traps stack-smashing attempts in hardware. On older CPUs, the OS silently falls back to standard software protection with zero performance impact.

---

## 3. Configuration & Deployment

Because general compiler and linker arguments cannot reside in the main `Cargo.toml`, they must be applied via a dedicated workspace configuration file.

### Step A: Configure High-Level Attributes in `Cargo.toml`
Keep your profile specifications lean by defining natively supported compiler behaviors inside your primary project file:

```toml
# Cargo.toml
[package]
name = "secure-windows-service"
version = "1.0.0"
edition = "2021"

[profile.release]
opt-level = 3
overflow-checks = true  # Catch math errors in release mode
panic = "abort"         # Strip unwinding metadata
```

### Step B: Apply Environment Flags in `.cargo/config.toml`
Create a folder named `.cargo/` in your root directory and place the following configuration file inside it. This routes target-specific properties directly to the MSVC toolchain:

```toml
# .cargo/config.toml

[target.x86_64-pc-windows-msvc]
rustflags = [
    # Enable Control Flow Guard (CFG) via compiler
    "-C", "control-flow-guard",
    
    # Secure Linker Directives for Windows Server 2019+
    "-C", "link-arg=/NXCOMPAT",        # DEP Enforced
    "-C", "link-arg=/DYNAMICBASE",     # ASLR Enforced
    "-C", "link-arg=/HIGHENTROPYVA",   # 64-Bit ASLR
    "-C", "link-arg=/CETCOMPAT",       # Hardware Shadow Stacks
    "-C", "link-arg=/GUARD:CF",        # Linker-level CFG tracking
]
```

---

## 4. Nightly Diagnostics (`-Z`)

If your project interfaces with legacy C/C++ libraries over the Foreign Function Interface (FFI) or uses high-volume `unsafe` code blocks, deploy these **Nightly-only** diagnostics in your testing/fuzzing environment to discover underlying vulnerabilities.

* **`-Z sanitizer=address`** (ASan)  
  Instruments allocations to capture use-after-free conditions and buffer overflows at runtime.
* **`-Z sanitizer=thread`** (TSan)  
  Monitors memory operations to pinpoint subtle multithreaded data races.

### Operational Routine (Testing/Fuzzing Only):
```bash
export RUSTFLAGS="-Z sanitizer=address"
cargo +nightly test -Z build-std --target x86_64-pc-windows-msvc
```
*(Note: Hardware-driven testing with `-Z build-std` requires explicitly defining your compilation target target system).*

//! Enforce the Windows build policy and embed ETW metadata/messages.
#![forbid(unsafe_code)]
use std::{env, error::Error, fs, io, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=events/BFD-Service.man");
    for variable in [
        "CARGO_ENCODED_RUSTFLAGS",
        "BFD_MC_PATH",
        "BFD_RC_PATH",
        "PATH",
        "WindowsSdkDir",
        "WindowsSDKVersion",
        "ProgramFiles(x86)",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    if env::var("CARGO_CFG_TARGET_OS")? != "windows" {
        return Ok(());
    }
    if env::var("TARGET")? != "x86_64-pc-windows-msvc" {
        return Err("the service supports only the 64-bit x86_64-pc-windows-msvc target".into());
    }
    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    for (prefix, option, required) in [
        ("-C", "control-flow-guard", "yes"),
        ("-C", "relocation-model", "pic"),
        ("-Z", "stack-protector", "all"),
        ("-Z", "ehcont-guard", "yes"),
        ("-Z", "src-hash-algorithm", "sha256"),
    ] {
        if !compiler_option_is(&flags, prefix, option, required) {
            return Err(format!(
                "the service requires {prefix}{option}={required}; use the repository's \
                 nightly toolchain and .cargo/config.toml without overriding its rustflags"
            )
            .into());
        }
    }
    for argument in [
        "/MACHINE:X64",
        "/DYNAMICBASE",
        "/HIGHENTROPYVA",
        "/NXCOMPAT",
        "/GUARD:CF",
        "/GUARD:EHCONT",
        "/CETCOMPAT",
        "/LARGEADDRESSAWARE",
    ] {
        println!("cargo:rustc-link-arg={argument}");
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest directory")?)
            .join("events/BFD-Service.man");
    run(Command::new(sdk_tool("mc.exe", "BFD_MC_PATH")?)
        .args(["-h", ".", "-r", "."])
        .arg(&manifest)
        .current_dir(&out))?;
    let resource = out.join("BFD-Service.res");
    run(Command::new(sdk_tool("rc.exe", "BFD_RC_PATH")?)
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg("BFD-Service.rc")
        .current_dir(&out))?;
    println!(
        "cargo:rustc-link-arg-bin=bfd-winservice={}",
        resource.display()
    );
    Ok(())
}

fn compiler_option_is(flags: &str, prefix: &str, name: &str, required: &str) -> bool {
    let mut flags = flags.split('\u{1f}');
    let mut setting = None;
    while let Some(flag) = flags.next() {
        let argument = if flag == prefix {
            flags.next()
        } else {
            flag.strip_prefix(prefix)
        };
        if let Some(value) = argument
            .and_then(|argument| argument.strip_prefix(name))
            .and_then(|value| value.strip_prefix('='))
        {
            setting = Some(value);
        }
    }
    setting == Some(required)
}

fn run(command: &mut Command) -> io::Result<()> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{command:?} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    Ok(())
}

fn sdk_tool(name: &str, override_variable: &str) -> io::Result<PathBuf> {
    if let Some(path) = env::var_os(override_variable) {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("PATH") {
        if let Some(tool) = env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|tool| tool.is_file())
        {
            return Ok(tool);
        }
    }
    let sdk = env::var_os("WindowsSdkDir").map(PathBuf::from).or_else(|| {
        env::var_os("ProgramFiles(x86)")
            .map(|directory| PathBuf::from(directory).join("Windows Kits/10"))
    });
    if let Some(sdk) = sdk {
        // These are host executables, even when compiling for a different target.
        let architecture = match env::consts::ARCH {
            "x86" => "x86",
            "aarch64" => "arm64",
            _ => "x64",
        };
        if let Some(version) = env::var_os("WindowsSDKVersion") {
            let tool = sdk.join("bin").join(version).join(architecture).join(name);
            if tool.is_file() {
                return Ok(tool);
            }
        }
        let mut versions: Vec<_> = fs::read_dir(sdk.join("bin"))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let version = entry
                    .file_name()
                    .to_str()?
                    .split('.')
                    .map(str::parse::<u32>)
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?;
                Some((version, entry.path()))
            })
            .collect();
        versions.sort_by(|left, right| right.0.cmp(&left.0));
        for (_, directory) in versions {
            let tool = directory.join(architecture).join(name);
            if tool.is_file() {
                return Ok(tool);
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, format!(
        "cannot find {name}; install the Windows SDK, use a Developer PowerShell, or set {override_variable}"
    )))
}

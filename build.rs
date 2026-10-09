//! Embed version and ETW resources for the supported Windows target.
#![forbid(unsafe_code)]
use std::{env, error::Error, fs, io, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=events/BFD-Service.man");
    println!("cargo:rerun-if-changed=resources/version.rc");
    for variable in [
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
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest directory")?)
            .join("events/BFD-Service.man");
    run(Command::new(sdk_tool("mc.exe", "BFD_MC_PATH")?)
        .args(["-h", ".", "-r", "."])
        .arg(&manifest)
        .current_dir(&out))?;
    let version = env::var("CARGO_PKG_VERSION")?;
    let major = env::var("CARGO_PKG_VERSION_MAJOR")?.parse::<u16>()?;
    let minor = env::var("CARGO_PKG_VERSION_MINOR")?.parse::<u16>()?;
    let patch = env::var("CARGO_PKG_VERSION_PATCH")?.parse::<u16>()?;
    fs::write(
        out.join("BFD-Version.rc"),
        format!(
            "#define BFD_FILE_VERSION {major},{minor},{patch},0\n\
             #define BFD_VERSION_TEXT \"{version}\\0\"\n{}",
            include_str!("resources/version.rc")
        ),
    )?;
    let resource_compiler = sdk_tool("rc.exe", "BFD_RC_PATH")?;
    for name in ["BFD-Service", "BFD-Version"] {
        let resource = out.join(format!("{name}.res"));
        run(Command::new(&resource_compiler)
            .arg("/nologo")
            .arg("/fo")
            .arg(&resource)
            .arg(format!("{name}.rc"))
            .current_dir(&out))?;
        println!(
            "cargo:rustc-link-arg-bin=bfd-winservice={}",
            resource.display()
        );
    }
    Ok(())
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

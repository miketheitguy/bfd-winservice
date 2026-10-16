//! Compile MIDL-generated stubs and the small structured-exception bridge.
use std::{collections::BTreeMap, io, path::Path, process::Command};
#[cfg(windows)]
use std::{env, path::PathBuf};

pub(super) fn build(out: &Path, root: &Path) -> io::Result<()> {
    for file in [
        "rpc/build.rs",
        "rpc/bfd_local.idl",
        "rpc/bfd_local_client.acf",
        "rpc/client.c",
        "rpc/server.c",
        "rpc/allocator.c",
    ] {
        println!("cargo:rerun-if-changed={file}");
    }
    for variable in [
        "BFD_MIDL_PATH",
        "BFD_VCVARS64_PATH",
        "VCToolsInstallDir",
        "VSINSTALLDIR",
        "INCLUDE",
        "LIB",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let environment = compiler_environment()?;
    let midl = super::sdk_tool("midl.exe", "BFD_MIDL_PATH")?;
    let sources = root.join("rpc");
    for (side, other) in [("client", "server"), ("server", "client")] {
        let mut command = Command::new(&midl);
        command
            .envs(&environment)
            .args(["/nologo", "/env", "x64", "/robust", "/Oicf", "/app_config"])
            .args(["/prefix", "client", "BfdClient_", "server", "BfdServer_"])
            .arg(format!("/{side}"))
            .arg("stub")
            .arg(format!("/{other}"))
            .arg("none")
            .arg("/h")
            .arg(format!("bfd_local_{side}.h"))
            .arg("/out")
            .arg(out)
            .arg(sources.join("bfd_local.idl"))
            .current_dir(out);
        if side == "client" {
            command
                .arg("/acf")
                .arg(sources.join("bfd_local_client.acf"));
        }
        run_compiler(&mut command)?;
    }
    for source in [
        out.join("bfd_local_c.c"),
        out.join("bfd_local_s.c"),
        sources.join("client.c"),
        sources.join("server.c"),
        sources.join("allocator.c"),
    ] {
        run_compiler(
            Command::new("cl.exe")
                .envs(&environment)
                .args([
                    "/nologo",
                    "/c",
                    "/MD",
                    "/GS",
                    "/guard:cf",
                    "/guard:ehcont",
                    "/sdl",
                    "/W4",
                    "/D_WIN32_WINNT=0x0602",
                ])
                .arg("/I")
                .arg(out)
                .arg(source)
                .current_dir(out),
        )?;
    }
    run_compiler(
        Command::new("lib.exe")
            .envs(&environment)
            .args([
                "/nologo",
                "/OUT:bfd_local_rpc.lib",
                "bfd_local_c.obj",
                "bfd_local_s.obj",
                "client.obj",
                "server.obj",
                "allocator.obj",
            ])
            .current_dir(out),
    )?;
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=bfd_local_rpc");
    println!("cargo:rustc-link-lib=Rpcrt4");
    Ok(())
}

fn run_compiler(command: &mut Command) -> io::Result<()> {
    let output = command.output()?;
    if output.status.success() {
        return Ok(());
    }
    // Command's Debug output includes environment overrides, which can contain
    // private values. Report only the executable and compiler diagnostics.
    Err(io::Error::other(format!(
        "{} failed: {}{}",
        command.get_program().to_string_lossy(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )))
}

#[cfg(windows)]
fn compiler_environment() -> io::Result<BTreeMap<String, String>> {
    use std::os::windows::process::CommandExt;

    let script = vcvars64()?;
    let output = Command::new("cmd.exe")
        .args(["/d", "/u", "/s", "/c"])
        .raw_arg(format!("\"\"{}\" >nul && set\"", script.display()))
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "MSVC environment setup failed; verify BFD_VCVARS64_PATH or repair the C++ Build Tools",
        ));
    }
    // Apply only compiler-related values to child processes. Do not mutate this
    // build script's environment, or copy unrelated credentials into commands.
    let utf16 = output
        .stdout
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .collect::<Vec<_>>();
    let environment = String::from_utf16(&utf16)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(environment
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| {
            ["PATH", "INCLUDE", "LIB", "LIBPATH"]
                .iter()
                .any(|expected| name.eq_ignore_ascii_case(expected))
        })
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect())
}

#[cfg(not(windows))]
fn compiler_environment() -> io::Result<BTreeMap<String, String>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "building Windows RPC stubs requires a Windows build host with MSVC and the Windows SDK",
    ))
}

#[cfg(windows)]
fn vcvars64() -> io::Result<PathBuf> {
    if let Some(path) = env::var_os("BFD_VCVARS64_PATH") {
        let script = PathBuf::from(path);
        if script.is_file() {
            return Ok(script);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "BFD_VCVARS64_PATH does not name an existing vcvars64.bat file",
        ));
    }
    if let Some(tools) = env::var_os("VCToolsInstallDir") {
        let tools = PathBuf::from(tools);
        for ancestor in tools.ancestors() {
            let script = ancestor.join("Auxiliary/Build/vcvars64.bat");
            if script.is_file() {
                return Ok(script);
            }
        }
    }
    if let Some(installation) = env::var_os("VSINSTALLDIR") {
        let script = PathBuf::from(installation).join("VC/Auxiliary/Build/vcvars64.bat");
        if script.is_file() {
            return Ok(script);
        }
    }
    if let Some(program_files) = env::var_os("ProgramFiles(x86)") {
        let locator =
            PathBuf::from(program_files).join("Microsoft Visual Studio/Installer/vswhere.exe");
        if locator.is_file() {
            let output = Command::new(locator)
                .args([
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property",
                    "installationPath",
                    "-utf8",
                ])
                .output()?;
            if output.status.success() {
                let installation = String::from_utf8_lossy(&output.stdout);
                let script =
                    PathBuf::from(installation.trim()).join("VC/Auxiliary/Build/vcvars64.bat");
                if script.is_file() {
                    return Ok(script);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "cannot find the MSVC x64 tools; install Visual Studio C++ Build Tools or set BFD_VCVARS64_PATH",
    ))
}

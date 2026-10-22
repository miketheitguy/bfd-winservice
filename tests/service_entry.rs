//! Executables reject foreground execution and removed command-line options.
#![cfg(all(windows, not(miri)))]
#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn service_binaries_reject_public_arguments_and_direct_execution() {
    for (executable, diagnostic) in [
        (env!("CARGO_BIN_EXE_bfd-winservice"), "BFD"),
        (env!("CARGO_BIN_EXE_bfd-bgp-broker"), "BGP broker"),
    ] {
        for arguments in [
            vec![],
            vec!["--console"],
            vec!["--help"],
            vec!["--version"],
            vec!["-h"],
            vec!["-V"],
        ] {
            let output = Command::new(executable)
                .args(&arguments)
                .output()
                .expect("service executable must launch");
            assert!(
                !output.status.success(),
                "{executable} accepted {arguments:?}"
            );
            assert!(output.stdout.is_empty(), "public output for {arguments:?}");
            let error = String::from_utf8(output.stderr).expect("daemon diagnostics use UTF-8");
            assert!(error.contains(diagnostic), "{error}");
        }
    }
}

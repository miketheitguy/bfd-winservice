#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::{io, io::Write, process};

#[cfg(windows)]
mod service;

fn main() {
    if std::env::args_os().nth(1).is_some() {
        let _ = writeln!(io::stderr().lock(), "BFD accepts no command-line arguments; start BfdWinService through the Service Control Manager");
        process::exit(1);
    }
    #[cfg(windows)]
    {
        if let Err(error) = service::run() {
            let _ = writeln!(io::stderr().lock(), "BFD failed: {error}");
            process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = writeln!(io::stderr().lock(), "The BFD service runs only on Windows.");
        process::exit(1);
    }
}

#![cfg_attr(test, allow(clippy::unwrap_used))]

use bfd_winservice::config::CommandLine;
use clap::Parser;
use std::process;

#[cfg(windows)]
use bfd_winservice::{
    config::load_registry,
    runtime::{Engine, Logger, StopSignal},
};
#[cfg(windows)]
use std::{error::Error, io, io::Write};

#[cfg(windows)]
mod service;

fn main() {
    let command_line = CommandLine::parse();
    #[cfg(windows)]
    {
        let result = if command_line.console {
            run_console()
        } else {
            service::run()
        };
        if let Err(error) = result {
            if !command_line.console {
                let _ = writeln!(io::stderr().lock(), "BFD failed: {error}");
            }
            process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = command_line;
        eprintln!("The BFD transport and service run only on Windows.");
        process::exit(1);
    }
}

#[cfg(windows)]
fn run_console() -> Result<(), Box<dyn Error>> {
    let mut log = Logger::new(true).inspect_err(|error| {
        let _ = writeln!(io::stderr().lock(), "unable to start BFD logger: {error}");
    })?;
    let result = (|| -> io::Result<()> {
        let options = load_registry(true)?;
        log.open_file(&options)?;
        let stop = StopSignal::new()?;
        let handler_stop = stop.clone();
        ctrlc::set_handler(move || {
            let _ = handler_stop.signal();
        })
        .map_err(io::Error::other)?;
        let mut engine = Engine::from_config(options, &mut log)?;
        log.service_started();
        engine.run_until(&stop, &mut log)
    })();
    if let Err(error) = &result {
        log.service_failed(error);
    }
    log.service_stopped(u32::from(result.is_err()));
    Ok(result?)
}

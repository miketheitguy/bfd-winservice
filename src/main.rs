use bfd_winservice::config::CommandLine;
use clap::Parser;
use std::process;

#[cfg(windows)]
use bfd_winservice::{
    config::load_registry,
    runtime::{Engine, Logger},
};
#[cfg(windows)]
use std::{error::Error, io, sync::mpsc};

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
                eprintln!("BFD failed: {error}");
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
    let mut log = Logger::new(true);
    let result = (|| -> io::Result<()> {
        let mut options = load_registry(true)?;
        let auth = options
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        log.open_file(&options)?;
        let (stop_tx, stop_rx) = mpsc::channel();
        ctrlc::set_handler(move || {
            let _ = stop_tx.send(());
        })
        .map_err(io::Error::other)?;
        let mut engine = Engine::open(options, auth, &mut log)?;
        log.service_started();
        engine.run(&stop_rx, &mut log)
    })();
    if let Err(error) = &result {
        log.service_failed(error);
    }
    log.service_stopped(u32::from(result.is_err()));
    Ok(result?)
}

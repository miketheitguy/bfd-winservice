use bfd_winservice::config::CommandLine;
use clap::Parser;

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
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = command_line;
        eprintln!("The BFD transport and service run only on Windows.");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run_console() -> Result<(), Box<dyn std::error::Error>> {
    let mut log = bfd_winservice::runtime::Logger::new(true);
    let result = (|| -> std::io::Result<()> {
        let mut options = bfd_winservice::config::load_registry(true)?;
        let auth = options
            .validate()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        log.open_file(options.log_file.as_deref())?;
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        ctrlc::set_handler(move || {
            let _ = stop_tx.send(());
        })
        .map_err(std::io::Error::other)?;
        let mut engine = bfd_winservice::runtime::Engine::open(options, auth, &mut log)?;
        log.service_started();
        engine.run(&stop_rx, &mut log)
    })();
    if let Err(error) = &result {
        log.service_failed(error);
    }
    log.service_stopped(u32::from(result.is_err()));
    result.map_err(Into::into)
}

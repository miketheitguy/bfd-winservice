use bfd_winservice::config::Options;
use clap::Parser;

#[cfg(windows)]
mod service;

fn main() {
    let mut options = Options::parse();
    let auth = match options.validate() {
        Ok(auth) => auth,
        Err(error) => {
            eprintln!("Configuration error: {error}");
            std::process::exit(2);
        }
    };
    #[cfg(windows)]
    {
        let result = if options.console {
            run_console(options, auth)
        } else {
            service::run(options, auth)
        };
        if let Err(error) = result {
            eprintln!("BFD failed: {error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = auth;
        eprintln!("The BFD transport and service run only on Windows.");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run_console(
    options: Options,
    auth: bfd_winservice::packet::AuthConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = stop_tx.send(());
    })?;
    let mut log = bfd_winservice::runtime::Logger::open(&options)?;
    let mut engine = bfd_winservice::runtime::Engine::open(options, auth, &mut log)?;
    engine.run(&stop_rx, &mut log)?;
    Ok(())
}

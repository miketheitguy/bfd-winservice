//! Entry point for the privileged BGP broker; packet handling stays in the BFD service.
#![forbid(unsafe_code)]

fn main() {
    #[cfg(windows)]
    if let Err(error) = bfd_winservice::bgp_broker::run() {
        eprintln!("BGP broker failed: {error}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("The BGP broker runs only on Windows.");
        std::process::exit(1);
    }
}

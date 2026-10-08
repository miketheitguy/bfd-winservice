//! Portable BFD configuration, packet authentication, and session state.
//!
//! On Windows, runtime and transport provide UDP execution; the executable also
//! supports SCM operation and optional native MI control of a local BGP peer.
pub mod config;
pub mod packet;
pub mod session;

#[cfg(windows)]
mod bgp;
#[cfg(windows)]
mod event_log;
#[cfg(windows)]
pub mod runtime;
#[cfg(windows)]
pub mod transport;

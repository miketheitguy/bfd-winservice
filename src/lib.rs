//! Portable classical/S-BFD configuration, authentication, session state,
//! and stateless S-BFD reflection.
//!
//! On Windows, runtime and transport provide UDP execution; the executable also
//! supports LocalService SCM operation and optional BGP control through a separate broker.
#![cfg_attr(test, allow(clippy::unwrap_used))]
pub mod config;
#[forbid(unsafe_code)]
pub mod error;
#[forbid(unsafe_code)]
pub mod packet;
#[forbid(unsafe_code)]
pub mod seamless;
#[forbid(unsafe_code)]
pub mod session;

#[cfg(windows)]
mod bgp;
#[cfg(windows)]
pub mod bgp_broker;
#[cfg(windows)]
mod event_log;
#[cfg(windows)]
pub mod runtime;
#[cfg(windows)]
pub mod transport;

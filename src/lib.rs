//! Portable classical/S-BFD configuration, authentication, session state,
//! and stateless S-BFD reflection.
//!
//! On Windows, runtime and transport provide UDP execution; the executable also
//! supports LocalService SCM operation and optional BGP control through a separate broker.
//! The installed service exposes private authenticated local RPC session telemetry.
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
mod com_security;
#[cfg(windows)]
mod event_log;
#[cfg(windows)]
pub mod local_rpc;
#[cfg(windows)]
pub mod runtime;
#[cfg(windows)]
mod service_identity;
#[cfg(windows)]
pub mod transport;

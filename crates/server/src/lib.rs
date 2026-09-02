//! Standalone Deaddrop relay server surfaces.

pub mod config;
pub mod debug;
pub mod maintenance;
pub mod shutdown;

mod connection;
#[cfg_attr(not(test), allow(dead_code))]
mod onion_http;
mod runtime;
#[cfg_attr(not(test), allow(dead_code))]
mod static_app;

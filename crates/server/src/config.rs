use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use thiserror::Error;

/// Standalone Deaddrop relay process.
#[derive(Debug, Parser)]
#[command(name = "deaddrop", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the explicit TCP/WebSocket debugging endpoint.
    Debug(DebugConfig),
}

#[derive(Debug, Args)]
pub struct DebugConfig {
    /// Socket address for the debug WebSocket endpoint.
    #[arg(long)]
    pub bind: SocketAddr,
    /// Private directory containing relay state.
    #[arg(long)]
    pub data_dir: PathBuf,
    /// Permit exposing the unauthenticated transport endpoint beyond loopback.
    #[arg(long)]
    pub unsafe_debug_bind: bool,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BindPolicyError {
    #[error("refusing non-loopback debug bind {0}; pass --unsafe-debug-bind to override")]
    UnsafeAddress(SocketAddr),
}

impl DebugConfig {
    pub fn validate_bind_policy(&self) -> Result<(), BindPolicyError> {
        if self.bind.ip().is_loopback() || self.unsafe_debug_bind {
            Ok(())
        } else {
            Err(BindPolicyError::UnsafeAddress(self.bind))
        }
    }
}

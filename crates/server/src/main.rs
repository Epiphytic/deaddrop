use std::process::ExitCode;

use clap::Parser;
use deaddrop_server::{
    config::{Cli, Command},
    debug::DebugServer,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        // Never accept dependency targets from RUST_LOG. Tungstenite's trace
        // records include complete frames; only our metadata-only targets are
        // allowed to emit diagnostics.
        .with_env_filter(EnvFilter::new("deaddrop=info,deaddrop_server=info"))
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(event = "debug_server_failed", error = %error);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let Cli {
        command: Command::Debug(config),
    } = Cli::parse();
    let unsafe_bind = config.unsafe_debug_bind;
    let requested_bind = config.bind;
    if unsafe_bind {
        tracing::warn!(
            event = "unsafe_debug_bind",
            bind = %requested_bind,
            "debug listener safety override is enabled"
        );
    }
    let server = DebugServer::start(config).await?;
    tracing::info!(
        event = "debug_listener_started",
        bind = %server.bound_addr(),
        transport = "websocket",
    );
    server.run_until_ctrl_c().await?;
    tracing::info!(event = "debug_listener_stopped");
    Ok(())
}

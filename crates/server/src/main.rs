use std::{io::Write, process::ExitCode};

use clap::Parser;
use deaddrop_server::{
    config::{Cli, Command, DebugConfig, RelayConfig},
    debug::DebugServer,
    onion::OnionRelay,
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
            tracing::error!(event = error.event, error = %error.error);
            ExitCode::FAILURE
        }
    }
}

struct ProcessError {
    event: &'static str,
    error: anyhow::Error,
}

async fn run() -> Result<(), ProcessError> {
    match Cli::parse().command {
        Command::Debug(config) => run_debug(config).await.map_err(|error| ProcessError {
            event: "debug_server_failed",
            error,
        }),
        Command::Relay(config) => run_relay(config).await.map_err(|error| ProcessError {
            event: "relay_failed",
            error,
        }),
    }
}

async fn run_debug(config: DebugConfig) -> anyhow::Result<()> {
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

async fn run_relay(config: RelayConfig) -> anyhow::Result<()> {
    let relay = OnionRelay::start(config).await?;
    let startup_result = {
        let mut stdout = std::io::stdout().lock();
        write_startup_record(&mut stdout, relay.startup_record())
    };
    if let Err(primary) = startup_result {
        if relay.shutdown().await.is_err() {
            tracing::warn!(
                event = "onion_startup_cleanup_failed",
                reason = "relay-runtime-shutdown"
            );
        }
        return Err(primary);
    }
    tracing::info!(event = "onion_relay_started", transport = "onion");
    relay.run_until_ctrl_c().await?;
    tracing::info!(event = "onion_relay_stopped");
    Ok(())
}

fn write_startup_record(
    writer: &mut impl Write,
    record: &deaddrop_server::onion::StartupRecord,
) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, record)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use deaddrop_server::onion::StartupRecord;

    use super::write_startup_record;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn record() -> StartupRecord {
        StartupRecord {
            onion_url: "http://example.onion".to_owned(),
            relay_url: "ws://example.onion/relay".to_owned(),
        }
    }

    #[test]
    fn startup_record_is_exactly_one_json_line() {
        let mut output = Vec::new();
        write_startup_record(&mut output, &record()).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "{\"onion_url\":\"http://example.onion\",\"relay_url\":\"ws://example.onion/relay\"}\n"
        );
    }

    #[test]
    fn startup_record_writer_failure_is_returned() {
        assert!(write_startup_record(&mut FailingWriter, &record()).is_err());
    }
}

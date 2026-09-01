use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use onion_probe::{OnionProbeConfig, launch};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let state_dir = state_dir_from_args()?;
    let config = OnionProbeConfig::production(state_dir);

    eprintln!(
        "{}",
        serde_json::json!({
            "event": "tor_bootstrap_start",
            "state_dir": config.state_dir,
        })
    );
    let (startup, running) = launch(&config).await?;
    println!(
        "{}",
        serde_json::to_string(&startup).context("failed to serialize startup record")?
    );

    let shutdown_signal = tokio::signal::ctrl_c();
    tokio::pin!(shutdown_signal);
    let mut supervision = tokio::time::interval(Duration::from_secs(1));
    let stopped_unexpectedly = loop {
        tokio::select! {
            result = &mut shutdown_signal => {
                result.context("failed to listen for shutdown signal")?;
                break false;
            }
            _ = supervision.tick() => {
                if running.is_finished() {
                    break true;
                }
            }
        }
    };

    if stopped_unexpectedly {
        running
            .wait()
            .await
            .context("onion HTTP service task failed")?;
        bail!("onion HTTP service stopped unexpectedly");
    } else {
        eprintln!("{}", serde_json::json!({"event": "shutdown_signal"}));
        running
            .shutdown()
            .await
            .context("failed to stop onion HTTP service cleanly")?;
    }

    Ok(())
}

fn state_dir_from_args() -> anyhow::Result<PathBuf> {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_else(|| "onion-probe".into());
    let Some(state_dir) = args.next() else {
        bail!(
            "usage: {} <TOR_STATE_DIR>",
            PathBuf::from(program).display()
        );
    };
    if args.next().is_some() {
        bail!(
            "usage: {} <TOR_STATE_DIR>",
            PathBuf::from(program).display()
        );
    }

    Ok(state_dir.into())
}

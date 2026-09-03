use std::time::Duration;

use deaddrop_relay_core::Clock;
use deaddrop_relay_sqlite::{Error, SqliteStore};
use tokio::time::{MissedTickBehavior, interval};

use crate::shutdown::ShutdownSignal;

/// Periodically remove expired ciphertext using trusted, injected time.
pub async fn run_maintenance<C>(
    store: SqliteStore,
    clock: C,
    period: Duration,
    mut shutdown: ShutdownSignal,
) -> Result<(), Error>
where
    C: Clock,
{
    assert!(!period.is_zero(), "maintenance interval must be non-zero");
    let mut ticks = interval(period);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            _ = ticks.tick() => {
                let removed = store.compact(clock.now_seconds()).await?;
                if removed > 0 {
                    tracing::info!(event = "relay_compaction", removed);
                }
            }
        }
    }
}

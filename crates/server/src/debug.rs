use std::{net::SocketAddr, path::PathBuf, time::Duration};

use deaddrop_relay_core::{RelayHub, SessionTask};
use deaddrop_relay_sqlite::{Error as StoreError, SqliteStore};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, mpsc},
    task::{JoinError, JoinHandle, JoinSet},
};

use crate::{
    config::{BindPolicyError, DebugConfig},
    connection::{SystemClock, TaskSubmitter, serve_connection},
    maintenance::run_maintenance,
    shutdown::{ShutdownSignal, ShutdownTrigger, shutdown_channel},
};

const SQLITE_QUEUE_CAPACITY: usize = 64;
const ACCEPTED_TASK_CAPACITY: usize = 128;
const ACCEPTED_TASK_CONCURRENCY: usize = 32;
const CONNECTION_CAPACITY: usize = 32;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    BindPolicy(#[from] BindPolicyError),
    #[error("failed to bind debug listener: {0}")]
    Bind(#[source] std::io::Error),
    #[error("failed to inspect bound debug listener: {0}")]
    LocalAddress(#[source] std::io::Error),
    #[error("failed to wait for shutdown signal: {0}")]
    Signal(#[source] std::io::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("debug server task failed: {0}")]
    Join(#[from] JoinError),
    #[error("expiry maintenance stopped unexpectedly")]
    MaintenanceStopped,
}

/// A running explicit debug listener. No production TCP listener is started.
pub struct DebugServer {
    bound_addr: SocketAddr,
    shutdown: ShutdownTrigger,
    completion: JoinHandle<Result<(), Error>>,
}

impl DebugServer {
    pub async fn start(config: DebugConfig) -> Result<Self, Error> {
        config.validate_bind_policy()?;
        let listener = TcpListener::bind(config.bind).await.map_err(Error::Bind)?;
        let bound_addr = listener.local_addr().map_err(Error::LocalAddress)?;
        let database_path = database_path(&config.data_dir);
        let store = SqliteStore::open(database_path, SQLITE_QUEUE_CAPACITY).await?;
        let hub = RelayHub::new(store.clone());
        let (shutdown, signal) = shutdown_channel();
        let completion = tokio::spawn(run_server(listener, hub, store, shutdown.clone(), signal));
        Ok(Self {
            bound_addr,
            shutdown,
            completion,
        })
    }

    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    pub async fn shutdown(self) -> Result<(), Error> {
        self.shutdown.trigger();
        self.completion.await??;
        Ok(())
    }

    /// Run until Ctrl-C or an internal server task stops unexpectedly.
    pub async fn run_until_ctrl_c(mut self) -> Result<(), Error> {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(Error::Signal)?;
                self.shutdown.trigger();
                self.completion.await??;
                Ok(())
            }
            result = &mut self.completion => {
                result??;
                Ok(())
            }
        }
    }
}

fn database_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("relay.sqlite3")
}

async fn run_server(
    listener: TcpListener,
    hub: RelayHub<SqliteStore>,
    store: SqliteStore,
    shutdown_trigger: ShutdownTrigger,
    mut shutdown: ShutdownSignal,
) -> Result<(), Error> {
    let (task_sender, task_receiver) = mpsc::channel(ACCEPTED_TASK_CAPACITY);
    let supervisor = tokio::spawn(supervise_tasks(task_receiver, ACCEPTED_TASK_CONCURRENCY));
    let (maintenance_stop, maintenance_signal) = shutdown_channel();
    let mut maintenance = tokio::spawn(run_maintenance(
        store.clone(),
        SystemClock,
        MAINTENANCE_INTERVAL,
        maintenance_signal,
    ));
    let mut connections = JoinSet::new();
    let connection_slots = std::sync::Arc::new(Semaphore::new(CONNECTION_CAPACITY));
    let mut maintenance_finished = None;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = &mut maintenance => {
                maintenance_finished = Some(result);
                shutdown_trigger.trigger();
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                            tracing::warn!(event = "debug_connection_rejected", reason = "connection-capacity");
                            drop(stream);
                            continue;
                        };
                        let local_addr = match stream.local_addr() {
                            Ok(local_addr) => local_addr,
                            Err(error) => {
                                tracing::warn!(event = "debug_connection_rejected", reason = "local-address", error_kind = ?error.kind());
                                continue;
                            }
                        };
                        let relay_url = match nostr::RelayUrl::parse(&format!("ws://{local_addr}")) {
                            Ok(relay_url) => relay_url,
                            Err(_) => {
                                tracing::warn!(event = "debug_connection_rejected", reason = "relay-url");
                                continue;
                            }
                        };
                        tracing::debug!(event = "debug_connection_opened", peer = %peer);
                        let connection_hub = hub.clone();
                        let connection_tasks = TaskSubmitter::new(task_sender.clone());
                        let connection_shutdown = shutdown.clone();
                        connections.spawn(async move {
                            let _permit = permit;
                            serve_connection(
                                stream,
                                peer,
                                relay_url,
                                connection_hub,
                                connection_tasks,
                                connection_shutdown,
                            ).await;
                        });
                    }
                    Err(error) => {
                        tracing::warn!(event = "debug_accept_failed", error_kind = ?error.kind());
                    }
                }
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(event = "debug_connection_task_failed", cancelled = error.is_cancelled(), panicked = error.is_panic());
                }
            }
        }
    }

    // Stop accepting, let sockets observe shutdown, and only then close task
    // admission. Every returned SessionTask is therefore either queued or was
    // completed inline by its submitting connection.
    drop(listener);
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            tracing::warn!(
                event = "debug_connection_task_failed",
                cancelled = error.is_cancelled(),
                panicked = error.is_panic()
            );
        }
    }
    drop(task_sender);
    if let Err(error) = supervisor.await {
        tracing::error!(
            event = "relay_task_supervisor_failed",
            cancelled = error.is_cancelled(),
            panicked = error.is_panic()
        );
    }

    let maintenance_was_early = maintenance_finished.is_some();
    let maintenance_result = if let Some(result) = maintenance_finished {
        result
    } else {
        maintenance_stop.trigger();
        maintenance.await
    };
    store.shutdown().await?;
    match maintenance_result {
        Ok(Ok(())) if maintenance_was_early => Err(Error::MaintenanceStopped),
        Ok(result) => result.map_err(Error::Store),
        Err(error) => Err(Error::Join(error)),
    }
}

async fn supervise_tasks(mut receiver: mpsc::Receiver<SessionTask>, max_running: usize) {
    assert!(max_running > 0, "task concurrency must be non-zero");
    let mut running = JoinSet::new();
    loop {
        if running.len() >= max_running {
            if let Some(Err(error)) = running.join_next().await {
                tracing::error!(
                    event = "relay_session_task_failed",
                    cancelled = error.is_cancelled(),
                    panicked = error.is_panic()
                );
            }
            continue;
        }
        tokio::select! {
            maybe_task = receiver.recv() => match maybe_task {
                Some(task) => { running.spawn(task); }
                None => break,
            },
            Some(result) = running.join_next(), if !running.is_empty() => {
                if let Err(error) = result {
                    tracing::error!(event = "relay_session_task_failed", cancelled = error.is_cancelled(), panicked = error.is_panic());
                }
            }
        }
    }
    while let Some(result) = running.join_next().await {
        if let Err(error) = result {
            tracing::error!(
                event = "relay_session_task_failed",
                cancelled = error.is_cancelled(),
                panicked = error.is_panic()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{sync::Semaphore, time::timeout};

    use super::*;

    fn gated_task(
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        release: Arc<Semaphore>,
    ) -> SessionTask {
        Box::pin(async move {
            let current = active.fetch_add(1, Ordering::AcqRel) + 1;
            peak.fetch_max(current, Ordering::AcqRel);
            let permit = release.acquire().await.unwrap();
            permit.forget();
            active.fetch_sub(1, Ordering::AcqRel);
        })
    }

    #[tokio::test]
    async fn task_supervisor_bounds_running_work_and_channel_backpressure() {
        let (sender, receiver) = mpsc::channel(1);
        let supervisor = tokio::spawn(supervise_tasks(receiver, 1));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));

        sender
            .send(gated_task(active.clone(), peak.clone(), release.clone()))
            .await
            .unwrap();
        while active.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        sender
            .send(gated_task(active.clone(), peak.clone(), release.clone()))
            .await
            .unwrap();
        let mut third =
            Box::pin(sender.send(gated_task(active.clone(), peak.clone(), release.clone())));
        assert!(
            timeout(Duration::from_millis(20), &mut third)
                .await
                .is_err(),
            "a full bounded supervisor must backpressure submission"
        );

        release.add_permits(1);
        third.await.unwrap();
        release.add_permits(2);
        drop(sender);
        supervisor.await.unwrap();
        assert_eq!(peak.load(Ordering::Acquire), 1);
    }
}

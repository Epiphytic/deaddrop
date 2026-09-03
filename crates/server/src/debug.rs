use std::{net::SocketAddr, path::PathBuf};

use deaddrop_relay_sqlite::Error as StoreError;
use thiserror::Error;
use tokio::{
    net::TcpListener,
    task::{JoinError, JoinHandle},
};

use crate::{
    config::{BindPolicyError, DebugConfig},
    connection::serve_connection,
    runtime::{ConnectionAdmissionError, Error as RuntimeError, RelayRuntime},
    shutdown::ShutdownTrigger,
};

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
    #[error("relay task supervisor stopped unexpectedly")]
    TaskSupervisorStopped,
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
        let database_path = database_path(&config.data_dir);
        let runtime = RelayRuntime::start(database_path)
            .await
            .map_err(map_runtime_error)?;
        Self::finish_start(config.bind, runtime).await
    }

    #[cfg(test)]
    async fn start_after_store_open<F>(config: DebugConfig, after_open: F) -> Result<Self, Error>
    where
        F: FnOnce(&deaddrop_relay_sqlite::SqliteStore),
    {
        config.validate_bind_policy()?;
        let database_path = database_path(&config.data_dir);
        let runtime = RelayRuntime::start_after_open(database_path, after_open)
            .await
            .map_err(map_runtime_error)?;
        Self::finish_start(config.bind, runtime).await
    }

    async fn finish_start(bind: SocketAddr, runtime: RelayRuntime) -> Result<Self, Error> {
        let listener = match TcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(error) => {
                return Err(cleanup_start_failure(runtime, Error::Bind(error)).await);
            }
        };
        let bound_addr = match listener.local_addr() {
            Ok(bound_addr) => bound_addr,
            Err(error) => {
                return Err(cleanup_start_failure(runtime, Error::LocalAddress(error)).await);
            }
        };
        let shutdown = runtime.shutdown_trigger();
        let completion = tokio::spawn(run_server(listener, runtime));
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

async fn run_server(listener: TcpListener, runtime: RelayRuntime) -> Result<(), Error> {
    let handle = runtime.handle();
    let mut shutdown = handle.shutdown_signal();
    let mut runtime_done = runtime.completion_signal();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = runtime_done.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
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
                        let connection_hub = handle.hub();
                        let connection_tasks = handle.task_submitter();
                        let connection_shutdown = handle.shutdown_signal();
                        match handle.try_register_connection(async move {
                            serve_connection(
                                stream,
                                peer,
                                relay_url,
                                connection_hub,
                                connection_tasks,
                                connection_shutdown,
                            ).await;
                        }) {
                            Ok(()) => {}
                            Err(ConnectionAdmissionError::AtCapacity) => {
                                tracing::warn!(event = "debug_connection_rejected", reason = "connection-capacity");
                            }
                            Err(ConnectionAdmissionError::ShuttingDown) => break,
                        }
                    }
                    Err(error) => {
                        tracing::warn!(event = "debug_accept_failed", error_kind = ?error.kind());
                    }
                }
            }
        }
    }

    drop(listener);
    runtime.shutdown().await.map_err(map_runtime_error)
}

fn map_runtime_error(error: RuntimeError) -> Error {
    match error {
        RuntimeError::Store(error) => Error::Store(error),
        RuntimeError::RuntimeJoin(error)
        | RuntimeError::MaintenanceJoin(error)
        | RuntimeError::TaskSupervisorJoin(error) => Error::Join(error),
        RuntimeError::MaintenanceStopped => Error::MaintenanceStopped,
        RuntimeError::TaskSupervisorStopped => Error::TaskSupervisorStopped,
    }
}

async fn cleanup_start_failure(runtime: RelayRuntime, primary: Error) -> Error {
    match runtime.shutdown().await {
        Ok(()) => primary,
        Err(_) => {
            tracing::warn!(
                event = "debug_startup_cleanup_failed",
                reason = "relay-runtime-shutdown"
            );
            primary
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use deaddrop_relay_sqlite::SqliteStore;
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn bind_failure_after_store_open_closes_sqlite_worker() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let temp = TempDir::new().unwrap();
        let captured: Arc<Mutex<Option<SqliteStore>>> = Arc::new(Mutex::new(None));
        let capture = Arc::clone(&captured);
        let result = DebugServer::start_after_store_open(
            DebugConfig {
                bind: occupied.local_addr().unwrap(),
                data_dir: temp.path().join("state"),
                unsafe_debug_bind: false,
            },
            move |store| {
                *capture.lock().unwrap() = Some(store.clone());
            },
        )
        .await;
        assert!(matches!(result, Err(Error::Bind(_))));
        let store = captured.lock().unwrap().take().unwrap();
        assert!(matches!(
            store.compact(1_700_000_000).await,
            Err(StoreError::WorkerStopped)
        ));
    }

    #[tokio::test]
    async fn runtime_panic_stops_listener_and_surfaces_join_error() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start_panicking(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let server = DebugServer::finish_start("127.0.0.1:0".parse().unwrap(), runtime)
            .await
            .unwrap();
        let bound_addr = server.bound_addr;
        let result = tokio::time::timeout(Duration::from_secs(1), server.completion)
            .await
            .expect("runtime panic left listener admission running")
            .unwrap();
        assert!(matches!(result, Err(Error::Join(_))));
        assert!(TcpListener::bind(bound_addr).await.is_ok());
    }

    #[tokio::test]
    async fn bind_error_remains_primary_when_runtime_cleanup_fails() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start_panicking(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let result = DebugServer::finish_start(occupied.local_addr().unwrap(), runtime).await;
        assert!(matches!(result, Err(Error::Bind(_))));
    }
}

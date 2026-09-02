use std::future::Future;

use hypertor::{OnionService, VanguardMode};
use serde::Serialize;
use thiserror::Error as ThisError;

use crate::{
    config::RelayConfig,
    onion_http::OnionHttpHost,
    runtime::{ConnectionAdmissionError, RelayRuntime},
    state::{StateDirectory, StateError},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StartupRecord {
    pub onion_url: String,
    pub relay_url: String,
}

impl StartupRecord {
    pub fn from_onion_address(onion_address: &str) -> Self {
        Self {
            onion_url: format!("http://{onion_address}"),
            relay_url: format!("ws://{onion_address}/relay"),
        }
    }
}

#[derive(Debug, ThisError)]
pub enum Error {
    #[error(transparent)]
    State(#[from] StateError),
    #[error("failed to start the relay runtime")]
    RuntimeStart,
    #[error("failed to launch the embedded onion service: {0}")]
    OnionLaunch(#[source] hypertor::Error),
    #[error("the embedded onion accept stream closed unexpectedly")]
    AcceptClosed,
    #[error("the relay runtime stopped unexpectedly")]
    RuntimeStopped,
    #[error("failed to drain the relay runtime")]
    RuntimeShutdown,
    #[error("failed to wait for shutdown signal: {0}")]
    Signal(#[source] std::io::Error),
}

/// Running production relay. The state-directory lock is held for its entire
/// lifetime, including orderly runtime draining.
pub struct OnionRelay {
    service: OnionService,
    runtime: RelayRuntime,
    state: StateDirectory,
    host: OnionHttpHost,
    startup: StartupRecord,
}

impl OnionRelay {
    pub async fn start(config: RelayConfig) -> Result<Self, Error> {
        let mut state = StateDirectory::acquire(&config.data_dir)?;
        let builder = OnionService::builder()
            .nickname(config.nickname())
            .map_err(Error::OnionLaunch)?;
        let runtime = RelayRuntime::start(state.database_path())
            .await
            .map_err(|_| Error::RuntimeStart)?;

        let launch = builder
            .state_dir(state.tor_dir())
            .port(config.virtual_port())
            .vanguards(VanguardMode::Full)
            .max_streams_per_circuit(8)
            .rate_limit_at_intro(4, 8)
            .launch();
        let (runtime, service) = launch_or_shutdown(runtime, launch)
            .await
            .map_err(Error::OnionLaunch)?;

        let onion_address = service.onion_address().to_owned();
        if let Err(primary) = state.validate_or_record_identity(&onion_address) {
            if shutdown_in_order(service, || runtime.shutdown())
                .await
                .is_err()
            {
                tracing::warn!(
                    event = "onion_startup_cleanup_failed",
                    reason = "relay-runtime-shutdown"
                );
            }
            return Err(Error::State(primary));
        }

        let startup = StartupRecord::from_onion_address(&onion_address);
        let host = OnionHttpHost::new(onion_address, runtime.handle());
        Ok(Self {
            service,
            runtime,
            state,
            host,
            startup,
        })
    }

    pub fn startup_record(&self) -> &StartupRecord {
        &self.startup
    }

    pub async fn shutdown(self) -> Result<(), Error> {
        let Self {
            service,
            runtime,
            state,
            host: _,
            startup: _,
        } = self;
        let _state = state;
        shutdown_in_order(service, || runtime.shutdown())
            .await
            .map_err(|_| Error::RuntimeShutdown)
    }

    pub async fn run_until_ctrl_c(self) -> Result<(), Error> {
        let Self {
            mut service,
            runtime,
            state,
            host,
            startup: _,
        } = self;
        let _state = state;
        let mut runtime_done = runtime.completion_signal();
        let outcome = loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    break signal.map_err(Error::Signal);
                }
                _ = runtime_done.cancelled() => break Err(Error::RuntimeStopped),
                stream = service.accept() => match stream {
                    Some(stream) => match host.try_serve(stream) {
                        Ok(()) => {}
                        Err(ConnectionAdmissionError::AtCapacity) => {
                            tracing::warn!(
                                event = "onion_connection_rejected",
                                reason = "connection-capacity"
                            );
                        }
                        Err(ConnectionAdmissionError::ShuttingDown) => {
                            break Err(Error::RuntimeStopped);
                        }
                    },
                    None => break Err(Error::AcceptClosed),
                }
            }
        };

        let cleanup = shutdown_in_order(service, || runtime.shutdown()).await;
        match (outcome, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(_), Err(_)) => Err(Error::RuntimeShutdown),
            (Err(primary), Ok(())) => Err(primary),
            (Err(primary), Err(_)) => {
                tracing::warn!(
                    event = "onion_shutdown_cleanup_failed",
                    reason = "relay-runtime-shutdown"
                );
                Err(primary)
            }
        }
    }
}

async fn launch_or_shutdown<T, E, F>(
    runtime: RelayRuntime,
    launch: F,
) -> Result<(RelayRuntime, T), E>
where
    F: Future<Output = Result<T, E>>,
{
    match launch.await {
        Ok(service) => Ok((runtime, service)),
        Err(primary) => {
            if runtime.shutdown().await.is_err() {
                tracing::warn!(
                    event = "onion_startup_cleanup_failed",
                    reason = "relay-runtime-shutdown"
                );
            }
            Err(primary)
        }
    }
}

async fn shutdown_in_order<S, F, Fut, T>(service: S, shutdown: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    drop(service);
    shutdown().await
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use deaddrop_relay_sqlite::{Error as StoreError, SqliteStore};
    use tempfile::TempDir;

    use super::{launch_or_shutdown, shutdown_in_order};
    use crate::runtime::RelayRuntime;

    struct DropRecorder(Arc<Mutex<Vec<&'static str>>>);

    impl Drop for DropRecorder {
        fn drop(&mut self) {
            self.0.lock().unwrap().push("service-dropped");
        }
    }

    #[tokio::test]
    async fn shutdown_drops_onion_service_before_draining_runtime() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let service = DropRecorder(Arc::clone(&events));
        let shutdown_events = Arc::clone(&events);

        shutdown_in_order(service, || async move {
            shutdown_events.lock().unwrap().push("runtime-drained");
            Ok::<_, ()>(())
        })
        .await
        .unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            vec!["service-dropped", "runtime-drained"]
        );
    }

    #[tokio::test]
    async fn launch_failure_after_runtime_start_closes_sqlite_worker() {
        let temp = TempDir::new().unwrap();
        let captured: Arc<Mutex<Option<SqliteStore>>> = Arc::new(Mutex::new(None));
        let capture = Arc::clone(&captured);
        let runtime =
            RelayRuntime::start_after_open(temp.path().join("state/relay.sqlite3"), move |store| {
                *capture.lock().unwrap() = Some(store.clone())
            })
            .await
            .unwrap();

        let result = launch_or_shutdown(runtime, async { Err::<(), _>("launch-failed") }).await;
        assert!(matches!(result, Err("launch-failed")));
        let store = captured.lock().unwrap().take().unwrap();
        assert!(matches!(
            store.compact(1_700_000_000).await,
            Err(StoreError::WorkerStopped)
        ));
    }
}

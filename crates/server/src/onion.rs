use std::{future::Future, io};

use hypertor::{OnionService, OnionStream, VanguardMode};
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
    host: OnionHttpHost,
    startup: StartupRecord,
}

impl OnionRelay {
    pub async fn start(config: RelayConfig) -> Result<Self, Error> {
        let mut state = StateDirectory::acquire(&config.data_dir)?;
        let builder = OnionService::builder()
            .nickname(config.nickname())
            .map_err(Error::OnionLaunch)?;
        let runtime = RelayRuntime::start_with_state(&state)
            .await
            .map_err(|_| Error::RuntimeStart)?;

        let launch = builder
            .state_dir(state.tor_dir())
            .port(config.virtual_port())
            .vanguards(VanguardMode::Full)
            .max_streams_per_circuit(8)
            .rate_limit_at_intro(4, 8)
            .launch();
        let (runtime, service) = match launch_or_shutdown(runtime, launch).await {
            Ok(launched) => launched,
            Err(LaunchFailure::Launch(error)) => return Err(Error::OnionLaunch(error)),
            Err(LaunchFailure::RuntimeStopped) => return Err(Error::RuntimeStopped),
        };

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
        let (runtime, service) = ensure_runtime_alive(runtime, service).await?;
        drop(state);
        Ok(Self {
            service,
            runtime,
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
            host: _,
            startup: _,
        } = self;
        shutdown_in_order(service, || runtime.shutdown())
            .await
            .map_err(|_| Error::RuntimeShutdown)
    }

    pub async fn run_until_ctrl_c(self) -> Result<(), Error> {
        let Self {
            mut service,
            runtime,
            host,
            startup: _,
        } = self;
        let runtime_done = runtime.completion_signal();
        let shutdown_signal = tokio::signal::ctrl_c();
        let outcome = run_accept_loop(&mut service, runtime_done, shutdown_signal, |stream| {
            host.try_serve(stream)
        })
        .await;

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

trait StreamAcceptor {
    type Stream;

    fn accept(&mut self) -> impl Future<Output = Option<Self::Stream>>;
}

impl StreamAcceptor for OnionService {
    type Stream = OnionStream;

    fn accept(&mut self) -> impl Future<Output = Option<Self::Stream>> {
        OnionService::accept(self)
    }
}

async fn run_accept_loop<A, S, F>(
    acceptor: &mut A,
    mut runtime_done: crate::shutdown::ShutdownSignal,
    shutdown_signal: S,
    mut admit: F,
) -> Result<(), Error>
where
    A: StreamAcceptor,
    S: Future<Output = Result<(), io::Error>>,
    F: FnMut(A::Stream) -> Result<(), ConnectionAdmissionError>,
{
    tokio::pin!(shutdown_signal);
    loop {
        tokio::select! {
            signal = &mut shutdown_signal => return signal.map_err(Error::Signal),
            _ = runtime_done.cancelled() => return Err(Error::RuntimeStopped),
            stream = acceptor.accept() => match stream {
                Some(stream) => match admit(stream) {
                    Ok(()) => {}
                    Err(ConnectionAdmissionError::AtCapacity) => {
                        tracing::warn!(
                            event = "onion_connection_rejected",
                            reason = "connection-capacity"
                        );
                    }
                    Err(ConnectionAdmissionError::ShuttingDown) => {
                        return Err(Error::RuntimeStopped);
                    }
                },
                None => return Err(Error::AcceptClosed),
            }
        }
    }
}

enum LaunchFailure<E> {
    Launch(E),
    RuntimeStopped,
}

async fn launch_or_shutdown<T, E, F>(
    runtime: RelayRuntime,
    launch: F,
) -> Result<(RelayRuntime, T), LaunchFailure<E>>
where
    F: Future<Output = Result<T, E>>,
{
    let mut runtime_done = runtime.completion_signal();
    tokio::pin!(launch);
    let launch_result = tokio::select! {
        biased;
        result = &mut launch => Some(result),
        _ = runtime_done.cancelled() => None,
    };
    match launch_result {
        Some(Ok(service)) if runtime_done.is_triggered() => {
            let _ = shutdown_in_order(service, || runtime.shutdown()).await;
            Err(LaunchFailure::RuntimeStopped)
        }
        Some(Ok(service)) => Ok((runtime, service)),
        Some(Err(primary)) => {
            if runtime.shutdown().await.is_err() {
                tracing::warn!(
                    event = "onion_startup_cleanup_failed",
                    reason = "relay-runtime-shutdown"
                );
            }
            Err(LaunchFailure::Launch(primary))
        }
        None => {
            let _ = runtime.shutdown().await;
            Err(LaunchFailure::RuntimeStopped)
        }
    }
}

async fn ensure_runtime_alive<T>(
    runtime: RelayRuntime,
    service: T,
) -> Result<(RelayRuntime, T), Error> {
    if runtime.completion_signal().is_triggered() {
        let _ = shutdown_in_order(service, || runtime.shutdown()).await;
        Err(Error::RuntimeStopped)
    } else {
        Ok((runtime, service))
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
    use std::{
        collections::VecDeque,
        future::{Future, poll_fn},
        io,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use deaddrop_relay_sqlite::{Error as StoreError, SqliteStore};
    use tempfile::TempDir;

    use super::{
        Error, LaunchFailure, StreamAcceptor, ensure_runtime_alive, launch_or_shutdown,
        run_accept_loop, shutdown_in_order,
    };
    use crate::{
        runtime::{ConnectionAdmissionError, RelayRuntime},
        shutdown::shutdown_channel,
    };

    struct DropRecorder(Arc<Mutex<Vec<&'static str>>>);

    impl Drop for DropRecorder {
        fn drop(&mut self) {
            self.0.lock().unwrap().push("service-dropped");
        }
    }

    struct ReadyAcceptor(VecDeque<u8>);

    impl StreamAcceptor for ReadyAcceptor {
        type Stream = u8;

        fn accept(&mut self) -> impl Future<Output = Option<Self::Stream>> {
            let mut stream = self.0.pop_front();
            poll_fn(move |_| match stream.take() {
                Some(stream) => Poll::Ready(Some(stream)),
                None => Poll::Pending,
            })
        }
    }

    struct StatefulSignal {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        ready_after: usize,
    }

    impl Future for StatefulSignal {
        type Output = Result<(), io::Error>;

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let polls = self.polls.fetch_add(1, Ordering::AcqRel) + 1;
            if polls >= self.ready_after {
                Poll::Ready(Ok(()))
            } else {
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    impl Drop for StatefulSignal {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[tokio::test]
    async fn ready_admissions_reuse_one_live_shutdown_signal() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let signal = StatefulSignal {
            polls: Arc::clone(&polls),
            drops: Arc::clone(&drops),
            ready_after: 3,
        };
        let mut acceptor = ReadyAcceptor(VecDeque::from([1, 2]));
        let (_runtime_trigger, runtime_done) = shutdown_channel();
        let mut admitted = Vec::new();

        let result = run_accept_loop(&mut acceptor, runtime_done, signal, |stream| {
            admitted.push(stream);
            Ok::<_, ConnectionAdmissionError>(())
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(admitted, vec![1, 2]);
        assert_eq!(polls.load(Ordering::Acquire), 3);
        assert_eq!(drops.load(Ordering::Acquire), 1);
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
        assert!(matches!(
            result,
            Err(LaunchFailure::Launch("launch-failed"))
        ));
        let store = captured.lock().unwrap().take().unwrap();
        assert!(matches!(
            store.compact(1_700_000_000).await,
            Err(StoreError::WorkerStopped)
        ));
    }

    #[tokio::test]
    async fn runtime_completion_during_launch_cannot_report_readiness() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start_panicking(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let mut runtime_done = runtime.completion_signal();
        let events = Arc::new(Mutex::new(Vec::new()));
        let service = DropRecorder(Arc::clone(&events));

        let result = launch_or_shutdown(runtime, async move {
            runtime_done.cancelled().await;
            Ok::<_, &'static str>(service)
        })
        .await;

        assert!(matches!(result, Err(LaunchFailure::RuntimeStopped)));
        drop(result);
        assert_eq!(*events.lock().unwrap(), vec!["service-dropped"]);
    }

    #[tokio::test]
    async fn completed_runtime_is_rejected_at_the_final_readiness_check() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start_panicking(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let mut runtime_done = runtime.completion_signal();
        runtime_done.cancelled().await;
        let events = Arc::new(Mutex::new(Vec::new()));
        let service = DropRecorder(Arc::clone(&events));

        let result = ensure_runtime_alive(runtime, service).await;

        assert!(matches!(result, Err(Error::RuntimeStopped)));
        assert_eq!(*events.lock().unwrap(), vec!["service-dropped"]);
    }
}

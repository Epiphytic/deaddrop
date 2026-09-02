use std::{future::Future, path::Path, pin::Pin, sync::Arc, time::Duration};

use deaddrop_relay_core::{RelayHub, SessionTask};
use deaddrop_relay_sqlite::{Error as StoreError, SqliteStore};
use thiserror::Error as ThisError;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::{JoinError, JoinHandle, JoinSet},
};

use crate::{
    connection::SystemClock,
    maintenance::run_maintenance,
    shutdown::{ShutdownSignal, ShutdownTrigger, shutdown_channel},
    state::{StateDirectory, StateLockLease},
};

const SQLITE_QUEUE_CAPACITY: usize = 64;
const ACCEPTED_TASK_CAPACITY: usize = 128;
const ACCEPTED_TASK_CONCURRENCY: usize = 32;
const CONNECTION_CAPACITY: usize = 32;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

type ConnectionTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[derive(Clone, Copy)]
struct RuntimeConfig {
    sqlite_queue_capacity: usize,
    accepted_task_capacity: usize,
    accepted_task_concurrency: usize,
    connection_capacity: usize,
    maintenance_interval: Duration,
    panic_after_start: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            sqlite_queue_capacity: SQLITE_QUEUE_CAPACITY,
            accepted_task_capacity: ACCEPTED_TASK_CAPACITY,
            accepted_task_concurrency: ACCEPTED_TASK_CONCURRENCY,
            connection_capacity: CONNECTION_CAPACITY,
            maintenance_interval: MAINTENANCE_INTERVAL,
            panic_after_start: false,
        }
    }
}

#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("relay runtime task failed: {0}")]
    RuntimeJoin(JoinError),
    #[error("expiry maintenance task failed: {0}")]
    MaintenanceJoin(JoinError),
    #[error("expiry maintenance stopped unexpectedly")]
    MaintenanceStopped,
    #[error("session-task supervisor failed: {0}")]
    TaskSupervisorJoin(JoinError),
    #[error("session-task supervisor stopped unexpectedly")]
    TaskSupervisorStopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionAdmissionError {
    AtCapacity,
    ShuttingDown,
}

#[derive(Clone)]
pub(crate) struct TaskSubmitter(mpsc::Sender<SessionTask>);

impl TaskSubmitter {
    pub(crate) fn new(sender: mpsc::Sender<SessionTask>) -> Self {
        Self(sender)
    }

    /// Once a session returns work, either transfer it to the runtime owner or
    /// drive it inline if that owner is already closing. Never cancel it.
    pub(crate) async fn submit(&self, task: SessionTask) {
        if let Err(error) = self.0.send(task).await {
            error.0.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn remaining_capacity(&self) -> usize {
        self.0.capacity()
    }
}

struct RegisteredConnection {
    task: ConnectionTask,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(crate) struct RuntimeHandle {
    hub: RelayHub<SqliteStore>,
    task_submitter: TaskSubmitter,
    connection_sender: mpsc::Sender<RegisteredConnection>,
    connection_slots: Arc<Semaphore>,
    shutdown: ShutdownSignal,
}

impl RuntimeHandle {
    pub(crate) fn hub(&self) -> RelayHub<SqliteStore> {
        self.hub.clone()
    }

    pub(crate) fn task_submitter(&self) -> TaskSubmitter {
        self.task_submitter.clone()
    }

    pub(crate) fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown.clone()
    }

    pub(crate) fn try_register_connection<F>(&self, task: F) -> Result<(), ConnectionAdmissionError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.shutdown.is_triggered() {
            return Err(ConnectionAdmissionError::ShuttingDown);
        }
        let permit = Arc::clone(&self.connection_slots)
            .try_acquire_owned()
            .map_err(|_| ConnectionAdmissionError::AtCapacity)?;
        let connection = RegisteredConnection {
            task: Box::pin(task),
            _permit: permit,
        };
        self.connection_sender
            .try_send(connection)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ConnectionAdmissionError::AtCapacity,
                mpsc::error::TrySendError::Closed(_) => ConnectionAdmissionError::ShuttingDown,
            })
    }
}

/// Shared native relay owner.
///
/// Dropping this value only signals best-effort asynchronous cleanup. Call and
/// await [`RelayRuntime::shutdown`] whenever complete connection, session-task,
/// maintenance, and SQLite draining is required.
pub(crate) struct RelayRuntime {
    handle: RuntimeHandle,
    shutdown: ShutdownTrigger,
    completion_signal: ShutdownSignal,
    completion: Option<JoinHandle<Result<(), Error>>>,
}

struct CompletionGuard {
    completion: ShutdownTrigger,
    state_lock: Option<StateLockLease>,
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        drop(self.state_lock.take());
        self.completion.trigger();
    }
}

impl RelayRuntime {
    pub(crate) async fn start(database_path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::start_with_config(database_path, RuntimeConfig::default()).await
    }

    pub(crate) async fn start_with_state(state: &StateDirectory) -> Result<Self, Error> {
        Self::start_state_runtime(state, std::future::ready(())).await
    }

    #[cfg(test)]
    async fn start_with_state_after<F>(
        state: &StateDirectory,
        before_open: F,
    ) -> Result<Self, Error>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self::start_state_runtime(state, before_open).await
    }

    async fn start_state_runtime<F>(state: &StateDirectory, before_open: F) -> Result<Self, Error>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let database_path = state.database_path();
        let state_lock = state.lock_lease();
        tokio::spawn(async move {
            before_open.await;
            Self::start_with_config_after_open_and_lock(
                database_path,
                RuntimeConfig::default(),
                |_| Ok(()),
                Some(state_lock),
            )
            .await
        })
        .await
        .map_err(Error::RuntimeJoin)?
    }

    #[cfg(test)]
    pub(crate) async fn start_after_open<F>(
        database_path: impl AsRef<Path>,
        after_open: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&SqliteStore),
    {
        Self::start_with_config_after_open(database_path, RuntimeConfig::default(), |store| {
            after_open(store);
            Ok(())
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn start_panicking(database_path: impl AsRef<Path>) -> Result<Self, Error> {
        let config = RuntimeConfig {
            panic_after_start: true,
            ..RuntimeConfig::default()
        };
        Self::start_with_config(database_path, config).await
    }

    async fn start_with_config(
        database_path: impl AsRef<Path>,
        config: RuntimeConfig,
    ) -> Result<Self, Error> {
        Self::start_with_config_after_open(database_path, config, |_| Ok(())).await
    }

    async fn start_with_config_after_open<F>(
        database_path: impl AsRef<Path>,
        config: RuntimeConfig,
        after_open: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&SqliteStore) -> Result<(), StoreError>,
    {
        Self::start_with_config_after_open_and_lock(database_path, config, after_open, None).await
    }

    async fn start_with_config_after_open_and_lock<F>(
        database_path: impl AsRef<Path>,
        config: RuntimeConfig,
        after_open: F,
        state_lock: Option<StateLockLease>,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&SqliteStore) -> Result<(), StoreError>,
    {
        assert!(config.accepted_task_capacity > 0);
        assert!(config.accepted_task_concurrency > 0);
        assert!(config.connection_capacity > 0);
        let store = SqliteStore::open(database_path, config.sqlite_queue_capacity).await?;
        if let Err(startup_error) = after_open(&store) {
            let cleanup = store.shutdown().await;
            return Err(startup_failure(startup_error, cleanup));
        }
        let hub = RelayHub::new(store.clone());
        let (task_sender, task_receiver) = mpsc::channel(config.accepted_task_capacity);
        let (connection_sender, connection_receiver) = mpsc::channel(config.connection_capacity);
        let (shutdown, shutdown_signal) = shutdown_channel();
        let handle = RuntimeHandle {
            hub,
            task_submitter: TaskSubmitter::new(task_sender),
            connection_sender,
            connection_slots: Arc::new(Semaphore::new(config.connection_capacity)),
            shutdown: shutdown_signal.clone(),
        };
        let (completion_trigger, completion_signal) = shutdown_channel();
        let runtime_shutdown = shutdown.clone();
        let completion = tokio::spawn(async move {
            let _completion = CompletionGuard {
                completion: completion_trigger,
                state_lock,
            };
            run_runtime(
                store,
                task_receiver,
                connection_receiver,
                runtime_shutdown,
                shutdown_signal,
                config,
            )
            .await
        });
        Ok(Self {
            handle,
            shutdown,
            completion_signal,
            completion: Some(completion),
        })
    }

    pub(crate) fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    pub(crate) fn shutdown_trigger(&self) -> ShutdownTrigger {
        self.shutdown.clone()
    }

    pub(crate) fn completion_signal(&self) -> ShutdownSignal {
        self.completion_signal.clone()
    }

    #[cfg(test)]
    pub(crate) fn trigger_shutdown(&self) {
        self.shutdown.trigger();
    }

    #[cfg(test)]
    pub(crate) async fn start_with_connection_capacity(
        database_path: impl AsRef<Path>,
        connection_capacity: usize,
    ) -> Result<Self, Error> {
        let config = RuntimeConfig {
            connection_capacity,
            ..RuntimeConfig::default()
        };
        Self::start_with_config(database_path, config).await
    }

    #[cfg(test)]
    pub(crate) async fn start_with_test_capacities(
        database_path: impl AsRef<Path>,
        connection_capacity: usize,
        accepted_task_capacity: usize,
        accepted_task_concurrency: usize,
    ) -> Result<Self, Error> {
        let config = RuntimeConfig {
            connection_capacity,
            accepted_task_capacity,
            accepted_task_concurrency,
            ..RuntimeConfig::default()
        };
        Self::start_with_config(database_path, config).await
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), Error> {
        self.shutdown.trigger();
        self.completion
            .take()
            .expect("relay runtime completion missing")
            .await
            .map_err(Error::RuntimeJoin)?
    }
}

impl Drop for RelayRuntime {
    fn drop(&mut self) {
        self.shutdown.trigger();
    }
}

fn startup_failure(primary: StoreError, cleanup: Result<(), StoreError>) -> Error {
    if cleanup.is_err() {
        tracing::warn!(
            event = "relay_startup_cleanup_failed",
            reason = "sqlite-shutdown"
        );
    }
    Error::Store(primary)
}

async fn run_runtime(
    store: SqliteStore,
    task_receiver: mpsc::Receiver<SessionTask>,
    mut connection_receiver: mpsc::Receiver<RegisteredConnection>,
    shutdown_trigger: ShutdownTrigger,
    mut shutdown: ShutdownSignal,
    config: RuntimeConfig,
) -> Result<(), Error> {
    assert!(!config.panic_after_start, "injected relay runtime panic");
    let (task_stop, task_stop_signal) = shutdown_channel();
    let mut task_supervisor = tokio::spawn(supervise_tasks(
        task_receiver,
        config.accepted_task_concurrency,
        task_stop_signal,
    ));
    let (maintenance_stop, maintenance_signal) = shutdown_channel();
    let mut maintenance = tokio::spawn(run_maintenance(
        store.clone(),
        SystemClock,
        config.maintenance_interval,
        maintenance_signal,
    ));
    let mut connections = JoinSet::new();
    let mut failure = None;
    let mut maintenance_finished = false;
    let mut supervisor_finished = false;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = &mut maintenance => {
                failure = Some(maintenance_failure(result));
                maintenance_finished = true;
                shutdown_trigger.trigger();
                break;
            }
            result = &mut task_supervisor => {
                failure = Some(supervisor_failure(result));
                supervisor_finished = true;
                shutdown_trigger.trigger();
                break;
            }
            connection = connection_receiver.recv() => match connection {
                Some(connection) => spawn_connection(&mut connections, connection),
                None => {
                    shutdown_trigger.trigger();
                    break;
                }
            },
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                log_connection_result(result);
            }
        }
    }

    shutdown_trigger.trigger();
    connection_receiver.close();
    while let Some(connection) = connection_receiver.recv().await {
        spawn_connection(&mut connections, connection);
    }
    while let Some(result) = connections.join_next().await {
        log_connection_result(result);
    }

    task_stop.trigger();
    if !supervisor_finished {
        let result = task_supervisor.await;
        if let Some(error) = unexpected_supervisor_result(result) {
            failure.get_or_insert(error);
        }
    }

    maintenance_stop.trigger();
    if !maintenance_finished {
        let result = maintenance.await;
        if let Some(error) = stopped_maintenance_failure(result) {
            failure.get_or_insert(error);
        }
    }

    if let Err(error) = store.shutdown().await {
        failure.get_or_insert(Error::Store(error));
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn spawn_connection(connections: &mut JoinSet<()>, connection: RegisteredConnection) {
    connections.spawn(async move {
        let _permit = connection._permit;
        connection.task.await;
    });
}

fn log_connection_result(result: Result<(), JoinError>) {
    if let Err(error) = result {
        tracing::warn!(
            event = "relay_connection_task_failed",
            cancelled = error.is_cancelled(),
            panicked = error.is_panic()
        );
    }
}

fn maintenance_failure(result: Result<Result<(), StoreError>, JoinError>) -> Error {
    match result {
        Ok(Ok(())) => Error::MaintenanceStopped,
        Ok(Err(error)) => Error::Store(error),
        Err(error) => Error::MaintenanceJoin(error),
    }
}

fn supervisor_failure(result: Result<(), JoinError>) -> Error {
    match result {
        Ok(()) => Error::TaskSupervisorStopped,
        Err(error) => Error::TaskSupervisorJoin(error),
    }
}

fn unexpected_supervisor_result(result: Result<(), JoinError>) -> Option<Error> {
    match result {
        Ok(()) => None,
        Err(error) => Some(Error::TaskSupervisorJoin(error)),
    }
}

fn stopped_maintenance_failure(result: Result<Result<(), StoreError>, JoinError>) -> Option<Error> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(Error::Store(error)),
        Err(error) => Some(Error::MaintenanceJoin(error)),
    }
}

async fn supervise_tasks(
    mut receiver: mpsc::Receiver<SessionTask>,
    max_running: usize,
    mut stop: ShutdownSignal,
) {
    assert!(max_running > 0, "task concurrency must be non-zero");
    let mut running = JoinSet::new();
    let mut closing = false;
    loop {
        if running.len() >= max_running {
            if let Some(result) = running.join_next().await {
                log_session_task_result(result);
            }
            continue;
        }
        tokio::select! {
            biased;
            _ = stop.cancelled(), if !closing => {
                receiver.close();
                closing = true;
            }
            maybe_task = receiver.recv() => match maybe_task {
                Some(task) => { running.spawn(task); }
                None => break,
            },
            Some(result) = running.join_next(), if !running.is_empty() => {
                log_session_task_result(result);
            }
        }
    }
    while let Some(result) = running.join_next().await {
        log_session_task_result(result);
    }
}

fn log_session_task_result(result: Result<(), JoinError>) {
    if let Err(error) = result {
        tracing::error!(
            event = "relay_session_task_failed",
            cancelled = error.is_cancelled(),
            panicked = error.is_panic()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use deaddrop_relay_core::{
        ChallengeSource, Clock, Session, SessionLimits, SessionOutput, StrictClientMessage,
    };
    use nostr::{EventBuilder, Filter, Keys, Kind, RelayMessage, RelayUrl, Timestamp};
    use tempfile::TempDir;
    use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

    use super::*;
    use crate::state::{StateDirectory, StateError};

    const NOW: u64 = 1_700_000_000;
    const ONION_ADDRESS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now_seconds(&self) -> u64 {
            NOW
        }
    }

    struct FixedChallenge;

    impl ChallengeSource for FixedChallenge {
        fn fill(&mut self, output: &mut [u8]) {
            output.fill(0x5a);
        }
    }

    fn test_config() -> RuntimeConfig {
        RuntimeConfig {
            sqlite_queue_capacity: 8,
            accepted_task_capacity: 4,
            accepted_task_concurrency: 1,
            connection_capacity: 1,
            maintenance_interval: Duration::from_secs(60),
            panic_after_start: false,
        }
    }

    fn session(
        hub: deaddrop_relay_core::RelayHub<deaddrop_relay_sqlite::SqliteStore>,
        relay_url: RelayUrl,
    ) -> Session<deaddrop_relay_sqlite::SqliteStore, FixedClock, FixedChallenge> {
        Session::new(
            hub,
            relay_url,
            FixedClock,
            FixedChallenge,
            SessionLimits::default(),
        )
    }

    async fn authenticate(
        session: &mut Session<deaddrop_relay_sqlite::SqliteStore, FixedClock, FixedChallenge>,
        relay_url: &RelayUrl,
        keys: &Keys,
    ) {
        let auth = EventBuilder::auth(session.challenge(), relay_url.clone())
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(keys)
            .unwrap();
        session.handle(StrictClientMessage::Auth(auth)).await;
    }

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
    async fn task_supervisor_bounds_running_work_and_handoff_queue() {
        let (sender, receiver) = mpsc::channel(1);
        let (stop, stop_signal) = shutdown_channel();
        let supervisor = tokio::spawn(supervise_tasks(receiver, 1, stop_signal));
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
            tokio::time::timeout(Duration::from_millis(20), &mut third)
                .await
                .is_err(),
            "a full bounded supervisor must backpressure task handoff"
        );

        release.add_permits(1);
        third.await.unwrap();
        stop.trigger();
        release.add_permits(2);
        supervisor.await.unwrap();
        assert_eq!(peak.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn task_handoff_after_admission_closes_is_completed_inline() {
        let temp = TempDir::new().unwrap();
        let runtime =
            RelayRuntime::start_with_config(temp.path().join("state/relay.sqlite3"), test_config())
                .await
                .unwrap();
        let submitter = runtime.handle().task_submitter();
        runtime.shutdown().await.unwrap();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_task = Arc::clone(&completed);
        submitter
            .submit(Box::pin(async move {
                completed_task.store(true, Ordering::Release);
            }))
            .await;
        assert!(completed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn startup_failure_after_store_open_closes_worker_before_returning() {
        let temp = TempDir::new().unwrap();
        let captured = Arc::new(std::sync::Mutex::new(None));
        let capture = Arc::clone(&captured);
        let result = RelayRuntime::start_with_config_after_open(
            temp.path().join("state/relay.sqlite3"),
            test_config(),
            move |store| {
                *capture.lock().unwrap() = Some(store.clone());
                Err(deaddrop_relay_sqlite::Error::WorkerStopped)
            },
        )
        .await;
        assert!(matches!(result, Err(Error::Store(_))));
        let store = captured.lock().unwrap().take().unwrap();
        assert!(matches!(
            store.compact(NOW).await,
            Err(deaddrop_relay_sqlite::Error::WorkerStopped)
        ));
    }

    #[test]
    fn startup_failure_preserves_primary_when_store_cleanup_also_fails() {
        let error = startup_failure(
            deaddrop_relay_sqlite::Error::UnsafeStatePath,
            Err(deaddrop_relay_sqlite::Error::WorkerStopped),
        );
        assert!(matches!(
            error,
            Error::Store(deaddrop_relay_sqlite::Error::UnsafeStatePath)
        ));
    }

    #[tokio::test]
    async fn dropping_runtime_signals_background_cleanup() {
        let temp = TempDir::new().unwrap();
        let captured = Arc::new(std::sync::Mutex::new(None));
        let capture = Arc::clone(&captured);
        let runtime =
            RelayRuntime::start_after_open(temp.path().join("state/relay.sqlite3"), move |store| {
                *capture.lock().unwrap() = Some(store.clone());
            })
            .await
            .unwrap();
        let store = captured.lock().unwrap().take().unwrap();
        drop(runtime);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match store.compact(NOW).await {
                    Err(deaddrop_relay_sqlite::Error::WorkerStopped) => break,
                    Ok(_) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected cleanup error: {error}"),
                }
            }
        })
        .await
        .expect("Drop did not trigger background runtime cleanup");
    }

    #[tokio::test]
    async fn dropped_runtime_retains_state_lock_until_admitted_work_drains() {
        let temp = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let data_dir = temp.path().join("state");
        let mut state = StateDirectory::acquire(&data_dir).unwrap();
        state.validate_or_record_identity(ONION_ADDRESS).unwrap();
        let runtime = RelayRuntime::start_with_state(&state).await.unwrap();
        let handle = runtime.handle();
        let mut completion = runtime.completion_signal();
        let (entered_sender, entered_receiver) = oneshot::channel();
        let release = Arc::new(Semaphore::new(0));
        let task_release = Arc::clone(&release);
        handle
            .try_register_connection(async move {
                entered_sender.send(()).unwrap();
                let permit = task_release.acquire().await.unwrap();
                permit.forget();
            })
            .unwrap();
        entered_receiver.await.unwrap();

        drop(state);
        drop(runtime);
        assert!(matches!(
            StateDirectory::acquire(&data_dir),
            Err(StateError::AlreadyRunning)
        ));

        release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), completion.cancelled())
            .await
            .expect("background runtime cleanup did not finish");
        StateDirectory::acquire(&data_dir)
            .expect("runtime completion must release the state lock last");
    }

    #[tokio::test]
    async fn cancelled_state_bound_startup_retains_lock_until_detached_cleanup() {
        let temp = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let data_dir = temp.path().join("state");
        let mut state = StateDirectory::acquire(&data_dir).unwrap();
        state.validate_or_record_identity(ONION_ADDRESS).unwrap();
        let (entered_sender, entered_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = oneshot::channel();
        let mut startup = Box::pin(RelayRuntime::start_with_state_after(&state, async move {
            entered_sender.send(()).unwrap();
            release_receiver.await.unwrap();
        }));
        tokio::select! {
            _ = &mut startup => panic!("state-bound startup completed before its gate"),
            result = entered_receiver => result.unwrap(),
        }

        drop(startup);
        drop(state);
        assert!(matches!(
            StateDirectory::acquire(&data_dir),
            Err(StateError::AlreadyRunning)
        ));

        release_sender.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match StateDirectory::acquire(&data_dir) {
                    Ok(state) => break state,
                    Err(StateError::AlreadyRunning) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected state reacquisition error: {error}"),
                }
            }
        })
        .await
        .expect("cancelled startup did not finish detached cleanup");
    }

    #[tokio::test]
    async fn connection_admission_is_bounded_and_shutdown_drains_admitted_work() {
        let temp = TempDir::new().unwrap();
        let runtime =
            RelayRuntime::start_with_config(temp.path().join("state/relay.sqlite3"), test_config())
                .await
                .unwrap();
        let handle = runtime.handle();
        let (entered_sender, entered_receiver) = oneshot::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_task = Arc::clone(&finished);
        let mut connection_shutdown = handle.shutdown_signal();
        handle
            .try_register_connection(async move {
                entered_sender.send(()).unwrap();
                connection_shutdown.cancelled().await;
                finished_task.store(true, Ordering::Release);
            })
            .unwrap();
        entered_receiver.await.unwrap();

        assert_eq!(
            handle.try_register_connection(std::future::pending()),
            Err(ConnectionAdmissionError::AtCapacity)
        );
        runtime.trigger_shutdown();
        assert_eq!(
            handle.try_register_connection(std::future::ready(())),
            Err(ConnectionAdmissionError::ShuttingDown)
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.shutdown())
            .await
            .expect("runtime did not drain an admitted half-open connection")
            .unwrap();
        assert!(finished.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn disconnected_publish_is_persisted_and_fanned_out_before_shutdown_finishes() {
        let temp = TempDir::new().unwrap();
        let database_path = temp.path().join("state/relay.sqlite3");
        let runtime = RelayRuntime::start_with_config(&database_path, test_config())
            .await
            .unwrap();
        let handle = runtime.handle();
        let relay_url = RelayUrl::parse("ws://examplehiddenservice.onion/relay").unwrap();
        let subscriber_keys = Keys::parse(&"11".repeat(32)).unwrap();
        let publisher_keys = Keys::parse(&"22".repeat(32)).unwrap();

        let mut subscriber = session(handle.hub(), relay_url.clone());
        authenticate(&mut subscriber, &relay_url, &subscriber_keys).await;
        subscriber
            .handle(StrictClientMessage::Req {
                subscription_id: nostr::SubscriptionId::new("profiles"),
                filters: vec![Filter::new().kind(Kind::Metadata)],
            })
            .await;
        while subscriber.next_output().is_some() {}

        let mut publisher = session(handle.hub(), relay_url.clone());
        authenticate(&mut publisher, &relay_url, &publisher_keys).await;
        let profile = EventBuilder::new(Kind::Metadata, r#"{"name":"alice"}"#)
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(&publisher_keys)
            .unwrap();
        let publish = publisher.handle(StrictClientMessage::Event(profile.clone()));
        let release = Arc::new(Notify::new());
        let release_task = Arc::clone(&release);
        let completed = Arc::new(AtomicBool::new(false));
        let completed_task = Arc::clone(&completed);
        handle
            .task_submitter()
            .submit(Box::pin(async move {
                release_task.notified().await;
                publish.await;
                completed_task.store(true, Ordering::Release);
            }))
            .await;
        publisher.disconnect();

        runtime.trigger_shutdown();
        let mut shutdown = Box::pin(runtime.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err(),
            "shutdown abandoned an accepted publish task"
        );
        release.notify_one();
        shutdown.await.unwrap();
        assert!(completed.load(Ordering::Acquire));
        assert!(
            std::iter::from_fn(|| subscriber.next_output()).any(|output| {
                matches!(
                    output,
                    SessionOutput::Send(RelayMessage::Event { event, .. }) if event.id == profile.id
                )
            })
        );
        assert_eq!(
            rusqlite::Connection::open(database_path)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn shutdown_drains_publish_blocked_behind_full_task_handoff() {
        let temp = TempDir::new().unwrap();
        let database_path = temp.path().join("state/relay.sqlite3");
        let mut config = test_config();
        config.accepted_task_capacity = 1;
        config.accepted_task_concurrency = 1;
        let runtime = RelayRuntime::start_with_config(&database_path, config)
            .await
            .unwrap();
        let handle = runtime.handle();
        let relay_url = RelayUrl::parse("ws://examplehiddenservice.onion/relay").unwrap();
        let subscriber_keys = Keys::parse(&"33".repeat(32)).unwrap();
        let publisher_keys = Keys::parse(&"44".repeat(32)).unwrap();

        let mut subscriber = session(handle.hub(), relay_url.clone());
        authenticate(&mut subscriber, &relay_url, &subscriber_keys).await;
        subscriber
            .handle(StrictClientMessage::Req {
                subscription_id: nostr::SubscriptionId::new("profiles"),
                filters: vec![Filter::new().kind(Kind::Metadata)],
            })
            .await;
        while subscriber.next_output().is_some() {}

        let running = Arc::new(AtomicBool::new(false));
        let running_task = Arc::clone(&running);
        let release = Arc::new(Semaphore::new(0));
        let release_task = Arc::clone(&release);
        let submitter = handle.task_submitter();
        submitter
            .submit(Box::pin(async move {
                running_task.store(true, Ordering::Release);
                let permit = release_task.acquire().await.unwrap();
                permit.forget();
            }))
            .await;
        while !running.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        submitter.submit(Box::pin(async {})).await;
        assert_eq!(submitter.0.capacity(), 0);

        let mut publisher = session(handle.hub(), relay_url.clone());
        authenticate(&mut publisher, &relay_url, &publisher_keys).await;
        let profile = EventBuilder::new(Kind::Metadata, r#"{"name":"queued"}"#)
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(&publisher_keys)
            .unwrap();
        let publish = publisher.handle(StrictClientMessage::Event(profile.clone()));
        let (handoff_started, handoff_observed) = oneshot::channel();
        let blocked_submitter = submitter.clone();
        handle
            .try_register_connection(async move {
                handoff_started.send(()).unwrap();
                blocked_submitter.submit(publish).await;
                publisher.disconnect();
            })
            .unwrap();
        handoff_observed.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(submitter.0.capacity(), 0);

        runtime.trigger_shutdown();
        let mut shutdown = Box::pin(runtime.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err(),
            "shutdown bypassed connection and task handoff drain"
        );
        release.add_permits(1);
        shutdown.await.unwrap();

        assert!(
            std::iter::from_fn(|| subscriber.next_output()).any(|output| {
                matches!(
                    output,
                    SessionOutput::Send(RelayMessage::Event { event, .. }) if event.id == profile.id
                )
            })
        );
        assert_eq!(
            rusqlite::Connection::open(database_path)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn unexpected_maintenance_termination_stops_and_fails_the_runtime() {
        let temp = TempDir::new().unwrap();
        let mut config = test_config();
        config.maintenance_interval = Duration::ZERO;
        let runtime =
            RelayRuntime::start_with_config(temp.path().join("state/relay.sqlite3"), config)
                .await
                .unwrap();
        let mut shutdown = runtime.handle().shutdown_signal();
        tokio::time::timeout(Duration::from_secs(1), shutdown.cancelled())
            .await
            .expect("maintenance failure did not stop admission");
        assert!(matches!(
            runtime.shutdown().await,
            Err(Error::MaintenanceJoin(_))
        ));
    }
}

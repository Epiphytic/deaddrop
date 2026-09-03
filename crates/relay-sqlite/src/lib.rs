//! SQLite persistence for the Deaddrop relay.
//!
//! Store commands enter a bounded worker queue when their returned future is
//! first polled. Dropping a future before it obtains queue capacity cancels the
//! command. Once accepted, the dedicated SQLite thread completes the command
//! independently even if its reply future or originating connection is
//! dropped. Relay drivers must therefore keep accepted publish tasks alive
//! through hub fan-out when delivery acknowledgements matter.

mod migrations;
mod worker;

use std::{io, path::Path, sync::Arc};

use deaddrop_protocol_core::{AuthorizedQuery, ValidatedEvent};
use deaddrop_relay_core::{Store, StoreFuture, StoreOutcome};
use futures::channel::oneshot;
use futures::lock::Mutex;
use nostr::Event;
use thiserror::Error as ThisError;

use worker::Command;

/// Failure to start or communicate with the SQLite worker.
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("SQLite command queue capacity must be greater than zero")]
    InvalidQueueCapacity,
    #[error("SQLite worker stopped")]
    WorkerStopped,
    #[error("SQLite state directory must not be accessible by group or other users")]
    InsecureDirectory,
    #[error("SQLite database path must include an explicit state directory")]
    MissingStateDirectory,
    #[error("SQLite database path must not traverse parent directories")]
    UnsafeStatePath,
    #[error("SQLite connection safety settings could not be enabled")]
    ConnectionConfiguration,
    #[error("SQLite schema version {actual} is newer than supported version {supported}")]
    UnsupportedSchema { actual: i64, supported: i64 },
    #[error("SQLite schema does not match its declared version")]
    MalformedSchema,
    #[error("timestamp {0} cannot be represented by SQLite")]
    TimestampOutOfRange(u64),
    #[error("result limit {0} cannot be represented by SQLite")]
    ResultLimitOutOfRange(usize),
    #[error("stored event failed integrity validation")]
    CorruptRow,
    #[error("failed to encode an internal query parameter: {0}")]
    Serialization(String),
    #[error("database operation failed: {0}")]
    Database(String),
    #[error("database file operation failed: {0}")]
    Io(String),
    #[error("failed to start SQLite worker: {0}")]
    Thread(String),
}

impl Error {
    fn database(error: rusqlite::Error) -> Self {
        Self::Database(error.to_string())
    }

    fn io(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }

    fn thread(error: io::Error) -> Self {
        Self::Thread(error.to_string())
    }
}

struct Inner {
    sender: async_channel::Sender<Command>,
    admission: Mutex<()>,
}

impl Inner {
    async fn send(&self, command: Command) -> Result<(), Error> {
        let _admission = self.admission.lock().await;
        self.sender
            .send(command)
            .await
            .map_err(|_| Error::WorkerStopped)
    }
}

/// Cloneable handle to one bounded, dedicated SQLite connection worker.
#[derive(Clone)]
pub struct SqliteStore {
    inner: Arc<Inner>,
}

impl SqliteStore {
    /// Open or migrate the database and start its dedicated worker thread.
    ///
    /// The database's parent is treated as a private state directory. Newly
    /// created directories use mode `0700` and database files use `0600` on
    /// Unix; an existing group/world-accessible directory is rejected.
    /// Opening, migration, and configuration execute on the dedicated thread;
    /// awaiting this future never performs database I/O on the caller's
    /// executor thread.
    pub fn open(
        path: impl AsRef<Path>,
        queue_capacity: usize,
    ) -> StoreFuture<'static, Result<Self, Error>> {
        let path = path.as_ref().to_path_buf();
        Box::pin(async move {
            let (sender, startup) = worker::spawn(path, queue_capacity)?;
            startup.await.map_err(|_| Error::WorkerStopped)??;
            Ok(Self {
                inner: Arc::new(Inner {
                    sender,
                    admission: Mutex::new(()),
                }),
            })
        })
    }

    /// Transactionally delete encrypted events whose expiry is at or before `now_seconds`.
    pub fn compact(&self, now_seconds: u64) -> StoreFuture<'_, Result<usize, Error>> {
        let (response, receiver) = oneshot::channel();
        let command = Command::Compact {
            now_seconds,
            response,
        };
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            inner.send(command).await?;
            receiver.await.map_err(|_| Error::WorkerStopped)?
        })
    }

    /// Close command admission and stop the worker after every command already
    /// admitted ahead of shutdown completes. Success is returned only after
    /// the worker has dropped its SQLite connection.
    pub fn shutdown(self) -> StoreFuture<'static, Result<(), Error>> {
        let (response, receiver) = oneshot::channel();
        let command = Command::Shutdown { response };
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _admission = inner.admission.lock().await;
            inner
                .sender
                .send(command)
                .await
                .map_err(|_| Error::WorkerStopped)?;
            inner.sender.close();
            drop(_admission);
            receiver.await.map_err(|_| Error::WorkerStopped)?
        })
    }
}

impl Store for SqliteStore {
    type Error = Error;

    fn query<'a>(
        &'a self,
        queries: &'a [AuthorizedQuery],
        now_seconds: u64,
        max_results: usize,
    ) -> StoreFuture<'a, Result<Vec<Event>, Self::Error>> {
        let (response, receiver) = oneshot::channel();
        let command = Command::Query {
            queries: queries.to_vec(),
            now_seconds,
            max_results,
            response,
        };
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            inner.send(command).await?;
            receiver.await.map_err(|_| Error::WorkerStopped)?
        })
    }

    fn put(&self, event: ValidatedEvent) -> StoreFuture<'_, Result<StoreOutcome, Self::Error>> {
        let (response, receiver) = oneshot::channel();
        let command = Command::Put {
            event: Box::new(event),
            response,
        };
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            inner.send(command).await?;
            receiver.await.map_err(|_| Error::WorkerStopped)?
        })
    }
}

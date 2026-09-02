use core::{fmt, future::Future, pin::Pin};

use deaddrop_protocol_core::{AuthorizedQuery, ValidatedEvent};
use nostr::Event;

/// Result of inserting an already validated event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOutcome {
    Stored,
    Duplicate,
    Superseded,
}

#[cfg(not(target_arch = "wasm32"))]
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub trait PlatformSendSync: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> PlatformSendSync for T {}

#[cfg(target_arch = "wasm32")]
pub trait PlatformSendSync {}

#[cfg(target_arch = "wasm32")]
impl<T> PlatformSendSync for T {}

/// Typed persistence boundary used by the socket-independent relay core.
///
/// Raw client filters and unvalidated events cannot cross this interface.
pub trait Store {
    type Error: fmt::Debug;

    fn query<'a>(
        &'a self,
        queries: &'a [AuthorizedQuery],
        now_seconds: u64,
        max_results: usize,
    ) -> StoreFuture<'a, Result<Vec<Event>, Self::Error>>;

    fn put(&self, event: ValidatedEvent) -> StoreFuture<'_, Result<StoreOutcome, Self::Error>>;
}

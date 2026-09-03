//! Socket-independent Deaddrop relay behavior.

mod auth;
mod hub;
mod session;
mod store;
mod wire;

pub use auth::{AUTH_FRESHNESS_SECONDS, AuthError, validate_auth_event};
pub use hub::{AuthorizedSubscription, CloseReason, RelayHub, SessionOutput, SessionToken};
pub use session::{ChallengeSource, Clock, Session, SessionLimits, SessionTask};
pub use store::{PlatformSendSync, Store, StoreFuture, StoreOutcome};
pub use wire::{StrictClientMessage, WireError, WireLimits, parse_client_message};

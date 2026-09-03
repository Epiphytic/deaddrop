//! Platform-neutral Deaddrop protocol types.

mod event_policy;
mod filter_policy;
pub mod kinds;
mod query;
mod retention;

pub use event_policy::{
    EventClass, EventPolicyError, MAX_EVENT_CONTENT_BYTES, ValidatedEvent, validate_write,
};
pub use filter_policy::{PolicyError, RejectionReason, authorize_filters};
pub use kinds::KIND_KEY_PACKAGE;
pub use query::{AuthorizedQuery, AuthorizedScope};

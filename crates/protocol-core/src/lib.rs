//! Platform-neutral Deaddrop protocol types.

mod filter_policy;
pub mod kinds;
mod query;

pub use filter_policy::{PolicyError, RejectionReason, authorize_filters};
pub use kinds::KIND_KEY_PACKAGE;
pub use query::{AuthorizedQuery, AuthorizedScope};

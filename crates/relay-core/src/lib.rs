//! Socket-independent Deaddrop relay behavior.

mod wire;

pub use wire::{StrictClientMessage, WireError, WireLimits, parse_client_message};

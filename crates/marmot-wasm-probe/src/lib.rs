pub mod error;
mod snapshot;
pub mod storage;

use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP};

pub fn probe_build_info() -> String {
    let _suite = cgka_engine::DEFAULT_CIPHERSUITE;
    serde_json::json!({
        "mdk_rev": "876bdf3c408df0658c158da6a6521745cd0abde5",
        "profile": "current",
        "kinds": [9, KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP, 30443],
    })
    .to_string()
}

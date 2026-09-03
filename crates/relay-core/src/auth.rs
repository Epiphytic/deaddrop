use nostr::{Event, Kind, PublicKey, RelayUrl};
use thiserror::Error;

/// NIP-42 authentication events are accepted within ten minutes of relay time.
pub const AUTH_FRESHNESS_SECONDS: u64 = 10 * 60;

/// Why a NIP-42 authentication event was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("the authentication event ID or signature is invalid")]
    InvalidSignature,
    #[error("the authentication event kind is invalid")]
    InvalidKind,
    #[error("the authentication event is outside the freshness window")]
    Stale,
    #[error("the authentication event envelope is invalid")]
    InvalidEnvelope,
}

/// Validate the complete NIP-42 event envelope for one connection challenge.
pub fn validate_auth_event(
    event: &Event,
    relay_url: &RelayUrl,
    challenge: &str,
    now_seconds: u64,
) -> Result<PublicKey, AuthError> {
    event.verify().map_err(|_| AuthError::InvalidSignature)?;
    if event.kind != Kind::Authentication {
        return Err(AuthError::InvalidKind);
    }

    let created_at = event.created_at.as_secs();
    let earliest = now_seconds.saturating_sub(AUTH_FRESHNESS_SECONDS);
    let latest = now_seconds.saturating_add(AUTH_FRESHNESS_SECONDS);
    if !(earliest..=latest).contains(&created_at) {
        return Err(AuthError::Stale);
    }

    let mut challenge_count = 0;
    let mut relay_count = 0;
    for tag in event.tags.iter() {
        let values = tag.as_slice();
        match values.first().map(String::as_str) {
            Some("challenge") => {
                if values.len() != 2 || values[1] != challenge {
                    return Err(AuthError::InvalidEnvelope);
                }
                challenge_count += 1;
            }
            Some("relay") => {
                if values.len() != 2 || values[1] != relay_url.as_str() {
                    return Err(AuthError::InvalidEnvelope);
                }
                relay_count += 1;
            }
            _ => {}
        }
    }
    if challenge_count != 1 || relay_count != 1 {
        return Err(AuthError::InvalidEnvelope);
    }

    Ok(event.pubkey)
}

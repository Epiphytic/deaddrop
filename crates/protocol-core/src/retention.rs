use crate::EventPolicyError;

pub(crate) const DAY_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const DEFAULT_ENCRYPTED_RETENTION_SECONDS: u64 = 7 * DAY_SECONDS;
pub(crate) const MAX_RETENTION_SECONDS: u64 = 30 * DAY_SECONDS;

pub(crate) fn encrypted_expiration(
    received_at: u64,
    requested: Option<u64>,
) -> Result<u64, EventPolicyError> {
    let default = received_at
        .checked_add(DEFAULT_ENCRYPTED_RETENTION_SECONDS)
        .ok_or(EventPolicyError::InvalidExpiration)?;
    let hard_cap = received_at
        .checked_add(MAX_RETENTION_SECONDS)
        .ok_or(EventPolicyError::InvalidExpiration)?;

    let requested = match requested {
        Some(expiration) if expiration <= received_at => {
            return Err(EventPolicyError::Expired);
        }
        Some(expiration) => expiration,
        None => default,
    };

    Ok(requested.min(default).min(hard_cap))
}

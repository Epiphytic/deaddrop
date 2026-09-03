use core::fmt;
use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use nostr::{Event, Kind, PublicKey, RelayUrl, Tag};
use thiserror::Error;

use crate::{KIND_KEY_PACKAGE, retention::encrypted_expiration};

/// Maximum ciphertext or public payload accepted by the application policy.
pub const MAX_EVENT_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_FUTURE_SKEW_SECONDS: u64 = 10 * 60;
const MARMOT_GROUP_CONTENT_MIN_BYTES: usize = 12 + 16;
const NIP44_V2_MIN_PAYLOAD_BYTES: usize = 1 + 32 + 2 + 32 + 32;
const NIP44_V2_MAX_PAYLOAD_BYTES: usize = 1 + 32 + 2 + 65_536 + 32;
const NIP44_V2_FIXED_OVERHEAD_BYTES: usize = 1 + 32 + 2 + 32;

/// The storage and authorization class proved for an accepted event.
#[derive(Clone, PartialEq, Eq)]
pub enum EventClass {
    Metadata,
    KeyPackage { d: String },
    Inbox { recipient: PublicKey },
    Group { h: [u8; 32] },
}

/// An event that passed signature, author, route, size, and retention policy.
///
/// All fields and construction remain private so persistence code can require
/// this proof without accepting a caller-fabricated value.
#[derive(Clone)]
pub struct ValidatedEvent {
    event: Event,
    class: EventClass,
    received_at: u64,
    expires_at: Option<u64>,
}

/// Why an event cannot cross the Deaddrop write-policy boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EventPolicyError {
    #[error("NIP-42 authentication is required before every write")]
    Unauthenticated,
    #[error("the event ID or signature is invalid")]
    InvalidSignature,
    #[error("the event author is not an authenticated key")]
    UnauthorizedAuthor,
    #[error("the event kind is not accepted by Deaddrop")]
    UnsupportedKind,
    #[error("the event created_at is too far in the future")]
    FutureDated,
    #[error("the event route tag shape or value is invalid")]
    InvalidRoute,
    #[error("the event payload encoding is invalid")]
    InvalidPayload,
    #[error("the NIP-40 expiration tag is invalid")]
    InvalidExpiration,
    #[error("the event was already expired when received")]
    Expired,
    #[error("event content contains {actual} bytes, exceeding the {max}-byte limit")]
    ContentTooLarge { actual: usize, max: usize },
}

/// Validate one signed event against the authenticated connection and storage
/// policy, returning a sealed proof suitable for persistence.
pub fn validate_write(
    authenticated_keys: &BTreeSet<PublicKey>,
    received_at: u64,
    event: Event,
) -> Result<ValidatedEvent, EventPolicyError> {
    if authenticated_keys.is_empty() {
        return Err(EventPolicyError::Unauthenticated);
    }
    event
        .verify()
        .map_err(|_| EventPolicyError::InvalidSignature)?;

    let content_bytes = event.content.len();
    if content_bytes > MAX_EVENT_CONTENT_BYTES {
        return Err(EventPolicyError::ContentTooLarge {
            actual: content_bytes,
            max: MAX_EVENT_CONTENT_BYTES,
        });
    }

    let (class, expires_at) = match event.kind {
        Kind::Metadata => {
            reject_future_timestamp(received_at, &event)?;
            require_authenticated_author(authenticated_keys, &event)?;
            (EventClass::Metadata, None)
        }
        kind if kind.as_u16() == KIND_KEY_PACKAGE => {
            reject_future_timestamp(received_at, &event)?;
            require_authenticated_author(authenticated_keys, &event)?;
            let d = validate_key_package(event.tags.as_slice(), &event.content)?;
            (EventClass::KeyPackage { d }, None)
        }
        Kind::GiftWrap => {
            let recipient = inbox_recipient(event.tags.as_slice())?;
            validate_nip44_payload(&event.content)?;
            let requested = expiration(event.tags.as_slice(), false)?;
            (
                EventClass::Inbox { recipient },
                Some(encrypted_expiration(received_at, requested)?),
            )
        }
        Kind::MlsGroupMessage => {
            reject_future_timestamp(received_at, &event)?;
            let (h, requested) = group_route(event.tags.as_slice())?;
            validate_group_payload(&event.content)?;
            (
                EventClass::Group { h },
                Some(encrypted_expiration(received_at, requested)?),
            )
        }
        _ => return Err(EventPolicyError::UnsupportedKind),
    };

    Ok(ValidatedEvent {
        event,
        class,
        received_at,
        expires_at,
    })
}

/// Validate only the public transport envelope. Recipients still parse the MLS
/// message and verify its credential identity, lifetime, reference, and
/// advertised capabilities against the current Marmot profile.
fn validate_key_package(tags: &[Tag], content: &str) -> Result<String, EventPolicyError> {
    const SINGLE_VALUE_TAGS: [&str; 4] = ["d", "mls_protocol_version", "i", "mls_ciphersuite"];
    const MULTI_VALUE_TAGS: [&str; 3] = ["mls_extensions", "mls_proposals", "app_components"];

    for name in SINGLE_VALUE_TAGS {
        let value = exact_named_value(tags, name)?;
        match name {
            "mls_protocol_version" if value != "1.0" => {
                return Err(EventPolicyError::InvalidRoute);
            }
            "i" if decode_lower_hex_32(value).is_none() => {
                return Err(EventPolicyError::InvalidRoute);
            }
            "mls_ciphersuite" if !is_lower_hex_u16(value) => {
                return Err(EventPolicyError::InvalidRoute);
            }
            _ => {}
        }
    }
    for name in MULTI_VALUE_TAGS {
        let values = exact_named_values(tags, name)?;
        let unique = values.iter().collect::<BTreeSet<_>>();
        if unique.len() != values.len() || values.iter().any(|value| !is_lower_hex_u16(value)) {
            return Err(EventPolicyError::InvalidRoute);
        }
    }
    if tags.len() != SINGLE_VALUE_TAGS.len() + MULTI_VALUE_TAGS.len() {
        return Err(EventPolicyError::InvalidRoute);
    }

    let decoded = decode_canonical_base64(content)?;
    if decoded.is_empty() {
        return Err(EventPolicyError::InvalidPayload);
    }

    Ok(exact_named_value(tags, "d")?.to_owned())
}

fn inbox_recipient(tags: &[Tag]) -> Result<PublicKey, EventPolicyError> {
    reject_unexpected_route_tags(tags, "p")?;
    let values = exact_named_tag(tags, "p")?;
    let valid_shape =
        values.len() == 2 || (values.len() == 3 && RelayUrl::parse(&values[2]).is_ok());
    if !valid_shape {
        return Err(EventPolicyError::InvalidRoute);
    }
    let value = &values[1];
    let recipient = PublicKey::from_hex(value).map_err(|_| EventPolicyError::InvalidRoute)?;
    if recipient.to_hex() != *value {
        return Err(EventPolicyError::InvalidRoute);
    }
    Ok(recipient)
}

fn exact_named_values<'a>(tags: &'a [Tag], name: &str) -> Result<&'a [String], EventPolicyError> {
    let mut matches = tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|value| value == name));
    let tag = matches.next().ok_or(EventPolicyError::InvalidRoute)?;
    if matches.next().is_some() {
        return Err(EventPolicyError::InvalidRoute);
    }
    let values = tag.as_slice();
    if values.len() < 2 || values[1..].iter().any(String::is_empty) {
        return Err(EventPolicyError::InvalidRoute);
    }
    Ok(&values[1..])
}

fn validate_nip44_payload(content: &str) -> Result<(), EventPolicyError> {
    let decoded = decode_canonical_base64(content)?;
    let padded_plaintext_bytes = decoded
        .len()
        .checked_sub(NIP44_V2_FIXED_OVERHEAD_BYTES)
        .ok_or(EventPolicyError::InvalidPayload)?;
    if !(NIP44_V2_MIN_PAYLOAD_BYTES..=NIP44_V2_MAX_PAYLOAD_BYTES).contains(&decoded.len())
        || decoded.first() != Some(&0x02)
        || nip44_padded_size(padded_plaintext_bytes) != padded_plaintext_bytes
    {
        return Err(EventPolicyError::InvalidPayload);
    }
    Ok(())
}

fn nip44_padded_size(plaintext_bytes: usize) -> usize {
    if plaintext_bytes <= 32 {
        return 32;
    }
    let next_power = plaintext_bytes.next_power_of_two();
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * (((plaintext_bytes - 1) / chunk) + 1)
}

fn validate_group_payload(content: &str) -> Result<(), EventPolicyError> {
    let decoded = decode_canonical_base64(content)?;
    if decoded.len() < MARMOT_GROUP_CONTENT_MIN_BYTES {
        return Err(EventPolicyError::InvalidPayload);
    }
    Ok(())
}

fn decode_canonical_base64(content: &str) -> Result<Vec<u8>, EventPolicyError> {
    let decoded = BASE64_STANDARD
        .decode(content.as_bytes())
        .map_err(|_| EventPolicyError::InvalidPayload)?;
    if BASE64_STANDARD.encode(&decoded) != content {
        return Err(EventPolicyError::InvalidPayload);
    }
    Ok(decoded)
}

fn reject_future_timestamp(received_at: u64, event: &Event) -> Result<(), EventPolicyError> {
    let latest = received_at.saturating_add(MAX_FUTURE_SKEW_SECONDS);
    if event.created_at.as_secs() > latest {
        Err(EventPolicyError::FutureDated)
    } else {
        Ok(())
    }
}

fn reject_unexpected_route_tags(tags: &[Tag], expected: &str) -> Result<(), EventPolicyError> {
    for tag in tags {
        let name = tag
            .as_slice()
            .first()
            .map(String::as_str)
            .ok_or(EventPolicyError::InvalidRoute)?;
        if matches!(name, "d" | "p" | "h") && name != expected {
            return Err(EventPolicyError::InvalidRoute);
        }
    }
    Ok(())
}

fn require_authenticated_author(
    authenticated_keys: &BTreeSet<PublicKey>,
    event: &Event,
) -> Result<(), EventPolicyError> {
    if authenticated_keys.contains(&event.pubkey) {
        Ok(())
    } else {
        Err(EventPolicyError::UnauthorizedAuthor)
    }
}

fn exact_named_value<'a>(tags: &'a [Tag], name: &str) -> Result<&'a str, EventPolicyError> {
    let values = exact_named_tag(tags, name)?;
    if values.len() != 2 || values[1].is_empty() {
        return Err(EventPolicyError::InvalidRoute);
    }
    Ok(&values[1])
}

fn exact_named_tag<'a>(tags: &'a [Tag], name: &str) -> Result<&'a [String], EventPolicyError> {
    let mut matches = tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|value| value == name));
    let tag = matches.next().ok_or(EventPolicyError::InvalidRoute)?;
    if matches.next().is_some() {
        return Err(EventPolicyError::InvalidRoute);
    }
    Ok(tag.as_slice())
}

fn expiration(tags: &[Tag], reject_unknown: bool) -> Result<Option<u64>, EventPolicyError> {
    let mut parsed = None;
    for tag in tags {
        let values = tag.as_slice();
        let Some(name) = values.first().map(String::as_str) else {
            return Err(EventPolicyError::InvalidRoute);
        };
        if name == "expiration" {
            if parsed.is_some() || values.len() != 2 {
                return Err(EventPolicyError::InvalidExpiration);
            }
            parsed = Some(
                values[1]
                    .parse::<u64>()
                    .map_err(|_| EventPolicyError::InvalidExpiration)?,
            );
        } else if reject_unknown && name != "h" {
            return Err(EventPolicyError::InvalidRoute);
        }
    }
    Ok(parsed)
}

fn group_route(tags: &[Tag]) -> Result<([u8; 32], Option<u64>), EventPolicyError> {
    let value = exact_named_value(tags, "h")?;
    let h = decode_lower_hex_32(value).ok_or(EventPolicyError::InvalidRoute)?;
    let expiration = expiration(tags, true)?;
    Ok((h, expiration))
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        decoded[index] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
    }
    Some(decoded)
}

fn is_lower_hex_u16(value: &str) -> bool {
    value.len() == 6
        && value.starts_with("0x")
        && value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl ValidatedEvent {
    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn class(&self) -> &EventClass {
        &self.class
    }

    pub fn received_at(&self) -> u64 {
        self.received_at
    }

    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }
}

impl fmt::Debug for ValidatedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedEvent")
            .field("id", &self.event.id)
            .field("kind", &self.event.kind)
            .field("pubkey", &self.event.pubkey)
            .field("class", &self.class)
            .field("content", &"[redacted]")
            .field("received_at", &self.received_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Debug for EventClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata => formatter.write_str("Metadata"),
            Self::KeyPackage { d } => formatter.debug_struct("KeyPackage").field("d", d).finish(),
            Self::Inbox { recipient } => formatter
                .debug_struct("Inbox")
                .field("recipient", recipient)
                .finish(),
            Self::Group { .. } => formatter
                .debug_struct("Group")
                .field("h", &"[redacted-capability]")
                .finish(),
        }
    }
}

use std::collections::BTreeSet;

use nostr::{Alphabet, Filter, Kind, PublicKey, SingleLetterTag};
use thiserror::Error;

use crate::{AuthorizedQuery, KIND_KEY_PACKAGE};

const P_TAG: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::P);
const H_TAG: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::H);

/// Why a syntactically valid Nostr filter is not a permitted Deaddrop read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RejectionReason {
    #[error("an explicit non-empty kinds set is required")]
    MissingKinds,
    #[error("the kinds set is unsupported or mixes authorization scopes")]
    UnsupportedKinds,
    #[error("NIP-50 search is not supported")]
    SearchUnsupported,
    #[error("the filter contains an unknown or misplaced tag constraint")]
    UnknownTag,
    #[error("the private route tag is missing")]
    MissingRoute,
    #[error("the private route tag must contain exactly one value")]
    AmbiguousRoute,
    #[error("the private route value is not an exact canonical value")]
    InvalidRoute,
    #[error("the inbox recipient is not an authenticated key")]
    UnauthorizedRecipient,
}

/// A complete REQ rejected by Deaddrop's read policy.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("NIP-42 authentication is required before every read")]
    Unauthenticated,
    #[error("REQ must contain at least one filter")]
    EmptyRequest,
    #[error("filter {index} is unauthorized: {reason}")]
    Rejected {
        index: usize,
        reason: RejectionReason,
    },
}

/// Authorize every OR-member of a Nostr REQ as one closed typed query.
///
/// The operation is atomic: one unauthorized member rejects the whole REQ and
/// no partial vector of broader reads can reach storage.
pub fn authorize_filters(
    authenticated_keys: &BTreeSet<PublicKey>,
    filters: &[Filter],
) -> Result<Vec<AuthorizedQuery>, PolicyError> {
    if authenticated_keys.is_empty() {
        return Err(PolicyError::Unauthenticated);
    }
    if filters.is_empty() {
        return Err(PolicyError::EmptyRequest);
    }

    filters
        .iter()
        .enumerate()
        .map(|(index, filter)| {
            authorize_filter(authenticated_keys, filter)
                .map_err(|reason| PolicyError::Rejected { index, reason })
        })
        .collect()
}

fn authorize_filter(
    authenticated_keys: &BTreeSet<PublicKey>,
    filter: &Filter,
) -> Result<AuthorizedQuery, RejectionReason> {
    if filter.search.is_some() {
        return Err(RejectionReason::SearchUnsupported);
    }

    let kinds = filter
        .kinds
        .as_ref()
        .filter(|kinds| !kinds.is_empty())
        .ok_or(RejectionReason::MissingKinds)?;

    if kinds.iter().all(is_public_kind) {
        if filter.generic_tags.is_empty() {
            return Ok(AuthorizedQuery::public(filter));
        }
        return Err(RejectionReason::UnknownTag);
    }

    if kinds.len() != 1 {
        return Err(RejectionReason::UnsupportedKinds);
    }

    match kinds.first().expect("the kinds set is non-empty") {
        Kind::GiftWrap => authorize_inbox(authenticated_keys, filter),
        Kind::MlsGroupMessage => authorize_group(filter),
        _ => Err(RejectionReason::UnsupportedKinds),
    }
}

fn authorize_inbox(
    authenticated_keys: &BTreeSet<PublicKey>,
    filter: &Filter,
) -> Result<AuthorizedQuery, RejectionReason> {
    let route = exact_route(filter, P_TAG)?;
    let recipient = PublicKey::from_hex(route).map_err(|_| RejectionReason::InvalidRoute)?;
    if recipient.to_hex() != route {
        return Err(RejectionReason::InvalidRoute);
    }
    if !authenticated_keys.contains(&recipient) {
        return Err(RejectionReason::UnauthorizedRecipient);
    }

    Ok(AuthorizedQuery::inbox(filter, recipient, route.to_owned()))
}

fn authorize_group(filter: &Filter) -> Result<AuthorizedQuery, RejectionReason> {
    let route = exact_route(filter, H_TAG)?;
    let capability = decode_lower_hex_32(route).ok_or(RejectionReason::InvalidRoute)?;
    Ok(AuthorizedQuery::group(filter, capability, route.to_owned()))
}

fn exact_route(filter: &Filter, expected_tag: SingleLetterTag) -> Result<&str, RejectionReason> {
    if filter.generic_tags.len() != 1 {
        return if filter.generic_tags.is_empty() {
            Err(RejectionReason::MissingRoute)
        } else {
            Err(RejectionReason::UnknownTag)
        };
    }

    let values = filter
        .generic_tags
        .get(&expected_tag)
        .ok_or(RejectionReason::UnknownTag)?;
    if values.len() != 1 {
        return Err(RejectionReason::AmbiguousRoute);
    }
    Ok(values.first().expect("the route set has one value"))
}

fn is_public_kind(kind: &Kind) -> bool {
    *kind == Kind::Metadata || kind.as_u16() == KIND_KEY_PACKAGE
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

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

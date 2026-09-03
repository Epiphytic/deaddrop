use core::fmt;
use std::collections::BTreeSet;

use nostr::{Alphabet, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp};

/// The authorization scope proved by an [`AuthorizedQuery`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedScope<'a> {
    /// Public profile metadata or key-package discovery.
    Public,
    /// A NIP-59 inbox belonging to an authenticated public key.
    Inbox(&'a PublicKey),
    /// An MLS group selected by possession of its exact random capability.
    Group(&'a [u8; 32]),
}

/// A query that passed Deaddrop's complete read-authorization policy.
///
/// Its representation and constructors are private so downstream storage and
/// fan-out code can require this type without accepting forged query scopes.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedQuery(AuthorizedQueryInner);

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizedQueryInner {
    scope: Scope,
    constraints: Constraints,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    Public,
    Inbox { recipient: PublicKey, route: String },
    Group { capability: [u8; 32], route: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Constraints {
    ids: Option<BTreeSet<EventId>>,
    authors: Option<BTreeSet<PublicKey>>,
    kinds: BTreeSet<Kind>,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
    limit: Option<usize>,
}

impl AuthorizedQuery {
    pub(crate) fn public(filter: &Filter) -> Self {
        Self::new(Scope::Public, filter)
    }

    pub(crate) fn inbox(filter: &Filter, recipient: PublicKey, route: String) -> Self {
        Self::new(Scope::Inbox { recipient, route }, filter)
    }

    pub(crate) fn group(filter: &Filter, capability: [u8; 32], route: String) -> Self {
        Self::new(Scope::Group { capability, route }, filter)
    }

    fn new(scope: Scope, filter: &Filter) -> Self {
        let constraints = Constraints {
            ids: filter.ids.clone(),
            authors: filter.authors.clone(),
            kinds: filter
                .kinds
                .clone()
                .expect("policy constructs queries only from explicit kinds"),
            since: filter.since,
            until: filter.until,
            limit: filter.limit,
        };
        Self(AuthorizedQueryInner { scope, constraints })
    }

    /// Return the query's proven public, inbox, or group scope.
    pub fn scope(&self) -> AuthorizedScope<'_> {
        match &self.0.scope {
            Scope::Public => AuthorizedScope::Public,
            Scope::Inbox { recipient, .. } => AuthorizedScope::Inbox(recipient),
            Scope::Group { capability, .. } => AuthorizedScope::Group(capability),
        }
    }

    /// Return the exact route tag used for a private scope.
    pub fn route_tag(&self) -> Option<(SingleLetterTag, &str)> {
        match &self.0.scope {
            Scope::Public => None,
            Scope::Inbox { route, .. } => Some((SingleLetterTag::lowercase(Alphabet::P), route)),
            Scope::Group { route, .. } => Some((SingleLetterTag::lowercase(Alphabet::H), route)),
        }
    }

    /// Optional exact event IDs retained from the client filter.
    pub fn ids(&self) -> Option<&BTreeSet<EventId>> {
        self.0.constraints.ids.as_ref()
    }

    /// Optional exact authors retained from the client filter.
    pub fn authors(&self) -> Option<&BTreeSet<PublicKey>> {
        self.0.constraints.authors.as_ref()
    }

    /// The explicit, policy-approved kinds for this query.
    pub fn kinds(&self) -> &BTreeSet<Kind> {
        &self.0.constraints.kinds
    }

    /// Optional inclusive lower timestamp bound.
    pub fn since(&self) -> Option<Timestamp> {
        self.0.constraints.since
    }

    /// Optional inclusive upper timestamp bound.
    pub fn until(&self) -> Option<Timestamp> {
        self.0.constraints.until
    }

    /// Optional result limit.
    pub fn limit(&self) -> Option<usize> {
        self.0.constraints.limit
    }
}

impl fmt::Debug for AuthorizedQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedQuery")
            .field("scope", &self.scope())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AuthorizedScope<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => formatter.write_str("Public"),
            Self::Inbox(recipient) => formatter.debug_tuple("Inbox").field(recipient).finish(),
            Self::Group(_) => formatter
                .debug_tuple("Group")
                .field(&"[redacted-capability]")
                .finish(),
        }
    }
}

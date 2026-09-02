use std::collections::BTreeSet;

use deaddrop_protocol_core::{AuthorizedScope, KIND_KEY_PACKAGE, PolicyError, authorize_filters};
use nostr::{Alphabet, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp};
use proptest::prelude::*;

const AUTH_KEY: [u8; 32] = [0x11; 32];
const OTHER_KEY: [u8; 32] = [0x22; 32];
const GROUP_H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn authenticated_keys() -> BTreeSet<PublicKey> {
    BTreeSet::from([PublicKey::from_byte_array(AUTH_KEY)])
}

fn tag(letter: Alphabet) -> SingleLetterTag {
    SingleLetterTag::lowercase(letter)
}

fn assert_rejected(filters: &[Filter]) {
    assert!(authorize_filters(&authenticated_keys(), filters).is_err());
}

#[test]
fn authorizes_each_public_discovery_kind_and_their_union() {
    let cases = [
        vec![Kind::Metadata],
        vec![Kind::from_u16(KIND_KEY_PACKAGE)],
        vec![Kind::Metadata, Kind::from_u16(KIND_KEY_PACKAGE)],
    ];

    for kinds in cases {
        let queries = authorize_filters(&authenticated_keys(), &[Filter::new().kinds(kinds)])
            .expect("the public discovery allowlist should be readable");

        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].scope(), AuthorizedScope::Public);
    }
}

#[test]
fn retains_safe_secondary_constraints_for_storage() {
    let id = EventId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
    let author = PublicKey::from_byte_array(OTHER_KEY);
    let filter = Filter::new()
        .kinds([Kind::Metadata, Kind::from_u16(KIND_KEY_PACKAGE)])
        .id(id)
        .author(author)
        .since(Timestamp::from(10))
        .until(Timestamp::from(20))
        .limit(5);

    let query = authorize_filters(&authenticated_keys(), &[filter])
        .unwrap()
        .pop()
        .unwrap();

    assert_eq!(query.ids().unwrap(), &BTreeSet::from([id]));
    assert_eq!(query.authors().unwrap(), &BTreeSet::from([author]));
    assert_eq!(
        query.kinds(),
        &BTreeSet::from([Kind::Metadata, Kind::from_u16(KIND_KEY_PACKAGE)])
    );
    assert_eq!(query.since(), Some(Timestamp::from(10)));
    assert_eq!(query.until(), Some(Timestamp::from(20)));
    assert_eq!(query.limit(), Some(5));
}

#[test]
fn authorizes_only_an_exact_authenticated_gift_wrap_recipient() {
    let recipient = PublicKey::from_byte_array(AUTH_KEY);
    let recipient_hex = recipient.to_hex();
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .custom_tag(tag(Alphabet::P), recipient_hex.clone());

    let query = authorize_filters(&authenticated_keys(), &[filter])
        .unwrap()
        .pop()
        .unwrap();

    assert_eq!(query.scope(), AuthorizedScope::Inbox(&recipient));
    assert_eq!(
        query.route_tag(),
        Some((tag(Alphabet::P), recipient_hex.as_str()))
    );
}

#[test]
fn authorizes_only_an_exact_lowercase_group_capability() {
    let filter = Filter::new()
        .kind(Kind::MlsGroupMessage)
        .custom_tag(tag(Alphabet::H), GROUP_H);

    let query = authorize_filters(&authenticated_keys(), &[filter])
        .unwrap()
        .pop()
        .unwrap();

    assert_eq!(
        query.scope(),
        AuthorizedScope::Group(&[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef
        ])
    );
    assert_eq!(query.route_tag(), Some((tag(Alphabet::H), GROUP_H)));
}

#[test]
fn rejects_broad_mixed_ambiguous_and_unsupported_filters() {
    let recipient = PublicKey::from_byte_array(AUTH_KEY);
    let other = PublicKey::from_byte_array(OTHER_KEY);
    let cases = [
        Filter::new(),
        Filter {
            kinds: Some(BTreeSet::new()),
            ..Filter::new()
        },
        Filter::new().kinds([Kind::Metadata, Kind::GiftWrap]),
        Filter::new().kinds([Kind::GiftWrap, Kind::MlsGroupMessage]),
        Filter::new().kind(Kind::TextNote),
        Filter::new().kind(Kind::GiftWrap),
        Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tags(tag(Alphabet::P), [recipient.to_hex(), other.to_hex()]),
        Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tag(tag(Alphabet::P), other.to_hex()),
        Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tag(tag(Alphabet::P), &recipient.to_hex()[..16]),
        Filter::new().kind(Kind::MlsGroupMessage),
        Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tags(tag(Alphabet::H), [GROUP_H, &"1".repeat(64)]),
        Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(tag(Alphabet::H), &GROUP_H[..16]),
        Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(tag(Alphabet::H), GROUP_H.to_uppercase()),
    ];

    for filter in cases {
        assert_rejected(&[filter]);
    }
}

#[test]
fn rejects_search_and_every_unrecognized_or_misplaced_tag() {
    let recipient = PublicKey::from_byte_array(AUTH_KEY);
    let cases = [
        Filter::new().kind(Kind::Metadata).search("profile"),
        Filter::new()
            .kind(Kind::Metadata)
            .custom_tag(tag(Alphabet::D), "identifier"),
        Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tag(tag(Alphabet::P), recipient.to_hex())
            .custom_tag(tag(Alphabet::E), "event"),
        Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(tag(Alphabet::H), GROUP_H)
            .custom_tag(tag(Alphabet::P), recipient.to_hex()),
        Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tag(SingleLetterTag::uppercase(Alphabet::P), recipient.to_hex()),
    ];

    for filter in cases {
        assert_rejected(&[filter]);
    }
}

#[test]
fn rejects_the_whole_req_when_any_or_filter_is_unauthorized() {
    let recipient = PublicKey::from_byte_array(AUTH_KEY);
    let public = Filter::new().kind(Kind::Metadata);
    let private = Filter::new()
        .kind(Kind::GiftWrap)
        .custom_tag(tag(Alphabet::P), recipient.to_hex());
    let unauthorized = Filter::new().kind(Kind::GiftWrap).custom_tag(
        tag(Alphabet::P),
        PublicKey::from_byte_array(OTHER_KEY).to_hex(),
    );

    let error = authorize_filters(
        &authenticated_keys(),
        &[public.clone(), private, unauthorized.clone()],
    )
    .unwrap_err();
    assert!(matches!(error, PolicyError::Rejected { index: 2, .. }));

    let error = authorize_filters(&authenticated_keys(), &[unauthorized, public]).unwrap_err();
    assert!(matches!(error, PolicyError::Rejected { index: 0, .. }));
}

#[test]
fn rejects_an_empty_or_filter_list() {
    assert!(matches!(
        authorize_filters(&authenticated_keys(), &[]),
        Err(PolicyError::EmptyRequest)
    ));
}

#[test]
fn rejects_every_scope_without_an_authenticated_key() {
    let recipient = PublicKey::from_byte_array(AUTH_KEY);
    let filters = [
        Filter::new().kind(Kind::Metadata),
        Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tag(tag(Alphabet::P), recipient.to_hex()),
        Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(tag(Alphabet::H), GROUP_H),
    ];

    for filter in filters {
        assert!(matches!(
            authorize_filters(&BTreeSet::new(), &[filter]),
            Err(PolicyError::Unauthenticated)
        ));
    }
}

#[test]
fn debug_output_redacts_group_capabilities() {
    let filter = Filter::new()
        .kind(Kind::MlsGroupMessage)
        .custom_tag(tag(Alphabet::H), GROUP_H);
    let query = authorize_filters(&authenticated_keys(), &[filter])
        .unwrap()
        .pop()
        .unwrap();

    let query_debug = format!("{query:?}");
    let scope_debug = format!("{:?}", query.scope());
    assert!(!query_debug.contains(GROUP_H));
    assert!(!scope_debug.contains(GROUP_H));
    assert!(query_debug.contains("redacted"));
}

proptest! {
    #[test]
    fn malformed_private_route_values_never_become_authorized(
        gift_wrap in any::<bool>(),
        bad_route in prop_oneof![
            "[0-9a-f]{0,63}",
            "[0-9a-f]{65,80}",
            "[g-zG-Z]{1,80}",
        ],
    ) {
        let (kind, route_tag) = if gift_wrap {
            (Kind::GiftWrap, tag(Alphabet::P))
        } else {
            (Kind::MlsGroupMessage, tag(Alphabet::H))
        };
        let filter = Filter::new().kind(kind).custom_tag(route_tag, bad_route);

        prop_assert!(authorize_filters(&authenticated_keys(), &[filter]).is_err());
    }
}

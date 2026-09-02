use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use deaddrop_protocol_core::{
    EventClass, EventPolicyError, MAX_EVENT_CONTENT_BYTES, validate_write,
};
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp};
use transport_nostr_peeler::NostrTransportEvent;

const RECEIVED_AT: u64 = 1_700_000_000;
const DAY: u64 = 24 * 60 * 60;
const GROUP_H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn keys(byte: u8) -> Keys {
    Keys::parse(&format!("{byte:02x}").repeat(32)).unwrap()
}

fn signed_event(keys: &Keys, kind: Kind, tags: Vec<Tag>, content: impl Into<String>) -> Event {
    EventBuilder::new(kind, content)
        .tags(tags)
        .custom_created_at(Timestamp::from(RECEIVED_AT))
        .sign_with_keys(keys)
        .unwrap()
}

fn tag(values: &[&str]) -> Tag {
    Tag::parse(values.iter().copied()).unwrap()
}

fn authenticated(keys: &Keys) -> BTreeSet<PublicKey> {
    BTreeSet::from([keys.public_key()])
}

fn key_package_tags() -> Vec<Tag> {
    vec![
        tag(&["d", "deaddrop"]),
        tag(&["mls_protocol_version", "1.0"]),
        tag(&["i", &"ab".repeat(32)]),
        tag(&["mls_ciphersuite", "0x0001"]),
        tag(&["mls_extensions", "0x0001"]),
        tag(&["mls_proposals", "0x0002"]),
        tag(&["app_components", "0xf001"]),
    ]
}

fn key_package_content() -> String {
    BASE64_STANDARD.encode([1, 2, 3])
}

fn nip44_content() -> String {
    let mut payload = vec![0_u8; 99];
    payload[0] = 0x02;
    BASE64_STANDARD.encode(payload)
}

fn group_content() -> String {
    BASE64_STANDARD.encode([0_u8; 28])
}

#[test]
fn accepts_author_bound_metadata_and_key_packages() {
    let account = keys(0x11);
    let auth = authenticated(&account);

    let metadata = validate_write(
        &auth,
        RECEIVED_AT,
        signed_event(&account, Kind::Metadata, vec![], r#"{"name":"marmot"}"#),
    )
    .unwrap();
    assert_eq!(metadata.class(), &EventClass::Metadata);
    assert_eq!(metadata.received_at(), RECEIVED_AT);
    assert_eq!(metadata.expires_at(), None);
    assert_eq!(metadata.event().pubkey, account.public_key());

    let package = validate_write(
        &auth,
        RECEIVED_AT,
        signed_event(
            &account,
            Kind::Custom(30_443),
            key_package_tags(),
            key_package_content(),
        ),
    )
    .unwrap();
    assert_eq!(
        package.class(),
        &EventClass::KeyPackage {
            d: "deaddrop".to_owned()
        }
    );
    assert_eq!(package.expires_at(), None);
}

#[test]
fn requires_authentication_and_binds_public_authors() {
    let account = keys(0x11);
    let other = keys(0x22);
    let event = signed_event(&other, Kind::Metadata, vec![], "{}");

    assert!(matches!(
        validate_write(&BTreeSet::new(), RECEIVED_AT, event.clone()),
        Err(EventPolicyError::Unauthenticated)
    ));
    assert!(matches!(
        validate_write(&authenticated(&account), RECEIVED_AT, event),
        Err(EventPolicyError::UnauthorizedAuthor)
    ));
}

#[test]
fn rejects_an_invalid_event_id_or_signature() {
    let account = keys(0x11);
    let mut event = signed_event(&account, Kind::Metadata, vec![], "{}");
    event.content = "tampered".to_owned();

    assert!(matches!(
        validate_write(&authenticated(&account), RECEIVED_AT, event),
        Err(EventPolicyError::InvalidSignature)
    ));
}

#[test]
fn key_packages_require_one_exact_nonempty_d_route() {
    let account = keys(0x11);
    let cases = [
        vec![],
        vec![tag(&["d"])],
        vec![tag(&["d", ""])],
        vec![tag(&["d", "one"]), tag(&["d", "two"])],
        vec![tag(&["d", "one", "extra"])],
        vec![
            tag(&["d", "one"]),
            tag(&["p", &keys(0x22).public_key().to_hex()]),
        ],
    ];

    for tags in cases {
        let event = signed_event(&account, Kind::Custom(30_443), tags, key_package_content());
        assert!(
            matches!(
                validate_write(&authenticated(&account), RECEIVED_AT, event),
                Err(EventPolicyError::InvalidRoute)
            ),
            "accepted malformed d route"
        );
    }
}

#[test]
fn rejects_future_dated_events_except_nip59_gift_wraps() {
    let connection = keys(0x11);
    let recipient = keys(0x22);
    let disposable = keys(0x33);
    let future = RECEIVED_AT + 11 * 60;

    let metadata = EventBuilder::new(Kind::Metadata, "{}")
        .custom_created_at(Timestamp::from(future))
        .sign_with_keys(&connection)
        .unwrap();
    assert!(matches!(
        validate_write(&authenticated(&connection), RECEIVED_AT, metadata),
        Err(EventPolicyError::FutureDated)
    ));

    let gift_wrap = EventBuilder::new(Kind::GiftWrap, nip44_content())
        .tag(tag(&["p", &recipient.public_key().to_hex()]))
        .custom_created_at(Timestamp::from(future))
        .sign_with_keys(&disposable)
        .unwrap();
    validate_write(&authenticated(&connection), RECEIVED_AT, gift_wrap)
        .expect("NIP-59 deliberately randomizes the outer created_at");
}

#[test]
fn permits_ephemeral_gift_wrap_author_and_uses_trusted_receive_time() {
    let connection = keys(0x11);
    let recipient = keys(0x22);
    let disposable = keys(0x33);
    let old_created_at = 100;
    let event = EventBuilder::new(Kind::GiftWrap, nip44_content())
        .tag(tag(&["p", &recipient.public_key().to_hex()]))
        .custom_created_at(Timestamp::from(old_created_at))
        .sign_with_keys(&disposable)
        .unwrap();

    let validated = validate_write(&authenticated(&connection), RECEIVED_AT, event).unwrap();
    assert_eq!(
        validated.class(),
        &EventClass::Inbox {
            recipient: recipient.public_key()
        }
    );
    assert_eq!(validated.expires_at(), Some(RECEIVED_AT + 7 * DAY));
}

#[test]
fn gift_wrap_requires_one_canonical_recipient_but_matches_marmot_route_shape() {
    let connection = keys(0x11);
    let recipient = keys(0x22);
    let disposable = keys(0x33);
    let recipient_hex = recipient.public_key().to_hex();

    let valid_shapes = [
        vec![tag(&["p", &recipient_hex])],
        // The pinned Marmot peeler accepts optional relay-hint fields on p tags.
        vec![tag(&["p", &recipient_hex, "wss://relay.invalid"])],
    ];
    for tags in valid_shapes {
        let event = signed_event(&disposable, Kind::GiftWrap, tags, nip44_content());
        NostrTransportEvent::from_nostr_event(&event)
            .unwrap()
            .to_transport_message()
            .expect("pinned Marmot accepts this gift-wrap route");
        validate_write(&authenticated(&connection), RECEIVED_AT, event)
            .expect("relay accepts every supported Marmot gift-wrap route");
    }

    let malformed_shapes = [
        vec![],
        vec![tag(&["p"])],
        vec![tag(&["p", "not-a-key"])],
        vec![tag(&["p", &recipient_hex]), tag(&["p", &recipient_hex])],
    ];
    for tags in malformed_shapes {
        let event = signed_event(&disposable, Kind::GiftWrap, tags, nip44_content());
        assert!(
            NostrTransportEvent::from_nostr_event(&event)
                .unwrap()
                .to_transport_message()
                .is_err()
        );
        assert!(matches!(
            validate_write(&authenticated(&connection), RECEIVED_AT, event),
            Err(EventPolicyError::InvalidRoute)
        ));
    }

    for tags in [
        vec![tag(&["p", &recipient_hex, "not-a-relay-url"])],
        vec![tag(&[
            "p",
            &recipient_hex,
            "wss://relay.invalid",
            "unexpected",
        ])],
    ] {
        let event = signed_event(&disposable, Kind::GiftWrap, tags, nip44_content());
        assert!(matches!(
            validate_write(&authenticated(&connection), RECEIVED_AT, event),
            Err(EventPolicyError::InvalidRoute)
        ));
    }

    let unknown_route = signed_event(
        &disposable,
        Kind::GiftWrap,
        vec![tag(&["p", &recipient_hex]), tag(&["h", GROUP_H])],
        nip44_content(),
    );
    assert!(matches!(
        validate_write(&authenticated(&connection), RECEIVED_AT, unknown_route),
        Err(EventPolicyError::InvalidRoute)
    ));
}

#[test]
fn group_routes_match_the_pinned_marmot_shape() {
    let connection = keys(0x11);
    let disposable = keys(0x33);
    let valid_shapes = [
        vec![tag(&["h", GROUP_H])],
        vec![
            tag(&["expiration", &(RECEIVED_AT + DAY).to_string()]),
            tag(&["h", GROUP_H]),
        ],
    ];
    for tags in valid_shapes {
        let event = signed_event(&disposable, Kind::MlsGroupMessage, tags, group_content());
        NostrTransportEvent::from_nostr_event(&event)
            .unwrap()
            .to_transport_message()
            .expect("pinned Marmot accepts this group route");
        let validated = validate_write(&authenticated(&connection), RECEIVED_AT, event).unwrap();
        assert_eq!(
            validated.class(),
            &EventClass::Group {
                h: [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
                    0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                ]
            }
        );
    }

    let malformed_shapes = [
        vec![],
        vec![tag(&["h", &GROUP_H.to_uppercase()])],
        vec![tag(&["h", &GROUP_H[..62]])],
        vec![tag(&["h", GROUP_H]), tag(&["h", GROUP_H])],
        vec![tag(&["h", GROUP_H, "extra"])],
        vec![tag(&["h", GROUP_H]), tag(&["e", &"11".repeat(32)])],
        vec![tag(&["h", GROUP_H]), tag(&["expiration", "nope"])],
        vec![
            tag(&["h", GROUP_H]),
            tag(&["expiration", "1700000001"]),
            tag(&["expiration", "1700000002"]),
        ],
    ];
    for tags in malformed_shapes {
        let event = signed_event(&disposable, Kind::MlsGroupMessage, tags, group_content());
        assert!(
            NostrTransportEvent::from_nostr_event(&event)
                .unwrap()
                .to_transport_message()
                .is_err()
        );
        assert!(matches!(
            validate_write(&authenticated(&connection), RECEIVED_AT, event),
            Err(EventPolicyError::InvalidRoute | EventPolicyError::InvalidExpiration)
        ));
    }
}

#[test]
fn encrypted_retention_defaults_to_seven_days_and_nip40_can_only_shorten_it() {
    let connection = keys(0x11);
    let recipient = keys(0x22);
    let disposable = keys(0x33);
    let recipient_hex = recipient.public_key().to_hex();

    for (requested, expected) in [
        (None, RECEIVED_AT + 7 * DAY),
        (Some(RECEIVED_AT + DAY), RECEIVED_AT + DAY),
        (Some(RECEIVED_AT + 20 * DAY), RECEIVED_AT + 7 * DAY),
        (Some(RECEIVED_AT + 40 * DAY), RECEIVED_AT + 7 * DAY),
    ] {
        let mut tags = vec![tag(&["p", &recipient_hex])];
        if let Some(expiration) = requested {
            tags.push(tag(&["expiration", &expiration.to_string()]));
        }
        let event = signed_event(&disposable, Kind::GiftWrap, tags, nip44_content());
        assert_eq!(
            validate_write(&authenticated(&connection), RECEIVED_AT, event)
                .unwrap()
                .expires_at(),
            Some(expected)
        );
    }
}

#[test]
fn rejects_expired_duplicate_malformed_and_unrepresentable_retention() {
    let connection = keys(0x11);
    let recipient = keys(0x22);
    let disposable = keys(0x33);
    let recipient_hex = recipient.public_key().to_hex();
    let cases = [
        vec![
            tag(&["p", &recipient_hex]),
            tag(&["expiration", "1699999999"]),
        ],
        vec![
            tag(&["p", &recipient_hex]),
            tag(&["expiration", "not-time"]),
        ],
        vec![
            tag(&["p", &recipient_hex]),
            tag(&["expiration", "1700000001"]),
            tag(&["expiration", "1700000002"]),
        ],
    ];
    for tags in cases {
        let event = signed_event(&disposable, Kind::GiftWrap, tags, nip44_content());
        assert!(validate_write(&authenticated(&connection), RECEIVED_AT, event).is_err());
    }

    let event = signed_event(
        &disposable,
        Kind::GiftWrap,
        vec![tag(&["p", &recipient_hex])],
        nip44_content(),
    );
    assert!(matches!(
        validate_write(&authenticated(&connection), u64::MAX, event),
        Err(EventPolicyError::InvalidExpiration)
    ));
}

#[test]
fn rejects_unknown_kinds_and_oversized_content() {
    let account = keys(0x11);
    let auth = authenticated(&account);
    let unknown = signed_event(&account, Kind::TextNote, vec![], "hello");
    assert!(matches!(
        validate_write(&auth, RECEIVED_AT, unknown),
        Err(EventPolicyError::UnsupportedKind)
    ));

    let oversized = signed_event(
        &account,
        Kind::Metadata,
        vec![],
        "x".repeat(MAX_EVENT_CONTENT_BYTES + 1),
    );
    assert!(matches!(
        validate_write(&auth, RECEIVED_AT, oversized),
        Err(EventPolicyError::ContentTooLarge { .. })
    ));
}

#[test]
fn rejects_structurally_incomplete_or_impossible_key_packages() {
    let account = keys(0x11);
    let auth = authenticated(&account);

    let mut missing_profile_tag = key_package_tags();
    missing_profile_tag.retain(|tag| tag.as_slice()[0] != "mls_proposals");
    let mut unknown_tag = key_package_tags();
    unknown_tag.push(tag(&["encoding", "base64"]));
    let mut duplicate_capability = key_package_tags();
    let extensions = duplicate_capability
        .iter_mut()
        .find(|tag| tag.as_slice()[0] == "mls_extensions")
        .unwrap();
    *extensions = tag(&["mls_extensions", "0x0001", "0x0001"]);
    let invalid_events = [
        signed_event(
            &account,
            Kind::Custom(30_443),
            missing_profile_tag,
            key_package_content(),
        ),
        signed_event(
            &account,
            Kind::Custom(30_443),
            key_package_tags(),
            "not-base64",
        ),
        signed_event(&account, Kind::Custom(30_443), key_package_tags(), ""),
        signed_event(
            &account,
            Kind::Custom(30_443),
            unknown_tag,
            key_package_content(),
        ),
        signed_event(
            &account,
            Kind::Custom(30_443),
            duplicate_capability,
            key_package_content(),
        ),
    ];

    for event in invalid_events {
        assert!(matches!(
            validate_write(&auth, RECEIVED_AT, event),
            Err(EventPolicyError::InvalidPayload | EventPolicyError::InvalidRoute)
        ));
    }
}

#[test]
fn rejects_impossible_encrypted_payload_encodings() {
    let connection = keys(0x11);
    let recipient = keys(0x22);
    let disposable = keys(0x33);
    let auth = authenticated(&connection);
    let p = tag(&["p", &recipient.public_key().to_hex()]);

    for content in [
        "not-base64".to_owned(),
        BASE64_STANDARD.encode([0x02_u8; 98]),
        BASE64_STANDARD.encode([0x02_u8; 100]),
        {
            let mut wrong_version = vec![0_u8; 99];
            wrong_version[0] = 0x01;
            BASE64_STANDARD.encode(wrong_version)
        },
        {
            let mut oversized = vec![0_u8; 65_604];
            oversized[0] = 0x02;
            BASE64_STANDARD.encode(oversized)
        },
    ] {
        let event = signed_event(&disposable, Kind::GiftWrap, vec![p.clone()], content);
        assert!(matches!(
            validate_write(&auth, RECEIVED_AT, event),
            Err(EventPolicyError::InvalidPayload)
        ));
    }

    for content in [
        "not-base64".to_owned(),
        BASE64_STANDARD.encode([0_u8; 27]),
        BASE64_STANDARD
            .encode([0_u8; 28])
            .trim_end_matches('=')
            .to_owned(),
    ] {
        let event = signed_event(
            &disposable,
            Kind::MlsGroupMessage,
            vec![tag(&["h", GROUP_H])],
            content,
        );
        assert!(matches!(
            validate_write(&auth, RECEIVED_AT, event),
            Err(EventPolicyError::InvalidPayload)
        ));
    }

    let mut maximum_payload = vec![0_u8; 65_603];
    maximum_payload[0] = 0x02;
    let event = signed_event(
        &disposable,
        Kind::GiftWrap,
        vec![p],
        BASE64_STANDARD.encode(maximum_payload),
    );
    validate_write(&auth, RECEIVED_AT, event).expect("pinned NIP-44 maximum remains accepted");
}

#[test]
fn validated_debug_redacts_content_and_private_routes() {
    let connection = keys(0x11);
    let disposable = keys(0x33);
    let event = signed_event(
        &disposable,
        Kind::MlsGroupMessage,
        vec![tag(&["h", GROUP_H])],
        group_content(),
    );
    let validated = validate_write(&authenticated(&connection), RECEIVED_AT, event).unwrap();

    let debug = format!("{validated:?}");
    assert!(!debug.contains(GROUP_H));
    assert!(!debug.contains(&group_content()));
    assert!(debug.contains("redacted"));
}

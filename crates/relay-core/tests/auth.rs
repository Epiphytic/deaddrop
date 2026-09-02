use deaddrop_relay_core::{AuthError, validate_auth_event};
use nostr::{Event, EventBuilder, Keys, Kind, RelayUrl, Tag, Timestamp};

const NOW: u64 = 1_700_000_000;
const CHALLENGE: &str = "connection-a-challenge";

fn keys(byte: u8) -> Keys {
    Keys::parse(&format!("{byte:02x}").repeat(32)).unwrap()
}

fn relay_url() -> RelayUrl {
    RelayUrl::parse("ws://127.0.0.1:8765").unwrap()
}

fn tag(values: &[&str]) -> Tag {
    Tag::parse(values.iter().copied()).unwrap()
}

fn auth_event(keys: &Keys, challenge: &str, relay: &RelayUrl, created_at: u64) -> Event {
    EventBuilder::auth(challenge, relay.clone())
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .unwrap()
}

#[test]
fn accepts_exact_fresh_signed_nip42_event() {
    let account = keys(0x11);
    let event = auth_event(&account, CHALLENGE, &relay_url(), NOW);

    let authenticated = validate_auth_event(&event, &relay_url(), CHALLENGE, NOW).unwrap();

    assert_eq!(authenticated, account.public_key());
}

#[test]
fn rejects_wrong_kind_relay_challenge_content_and_tag_shape() {
    let account = keys(0x11);
    let relay = relay_url();
    let other_relay = RelayUrl::parse("ws://127.0.0.1:9999").unwrap();
    let cases = [
        EventBuilder::new(Kind::TextNote, "")
            .tags([
                tag(&["challenge", CHALLENGE]),
                tag(&["relay", relay.as_str()]),
            ])
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(&account)
            .unwrap(),
        auth_event(&account, "wrong", &relay, NOW),
        auth_event(&account, CHALLENGE, &other_relay, NOW),
        EventBuilder::new(Kind::Authentication, "")
            .tags([
                tag(&["challenge", CHALLENGE]),
                tag(&["challenge", CHALLENGE]),
                tag(&["relay", relay.as_str()]),
            ])
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(&account)
            .unwrap(),
        EventBuilder::new(Kind::Authentication, "")
            .tags([
                tag(&["challenge", CHALLENGE, "extra"]),
                tag(&["relay", relay.as_str()]),
            ])
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(&account)
            .unwrap(),
    ];

    for (index, event) in cases.into_iter().enumerate() {
        assert!(
            validate_auth_event(&event, &relay, CHALLENGE, NOW).is_err(),
            "accepted non-exact NIP-42 envelope case {index}"
        );
    }
}

#[test]
fn permits_nonempty_content_and_unrelated_tags() {
    let account = keys(0x11);
    let relay = relay_url();
    let event = EventBuilder::new(Kind::Authentication, "client note")
        .tags([
            tag(&["challenge", CHALLENGE]),
            tag(&["relay", relay.as_str()]),
            tag(&["p", &keys(0x22).public_key().to_hex()]),
        ])
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(&account)
        .unwrap();

    assert_eq!(
        validate_auth_event(&event, &relay, CHALLENGE, NOW),
        Ok(account.public_key())
    );
}

#[test]
fn verifies_event_id_and_signature() {
    let account = keys(0x11);
    let mut event = auth_event(&account, CHALLENGE, &relay_url(), NOW);
    event.content = "tampered".to_owned();

    assert_eq!(
        validate_auth_event(&event, &relay_url(), CHALLENGE, NOW),
        Err(AuthError::InvalidSignature)
    );
}

#[test]
fn enforces_inclusive_ten_minute_freshness_window() {
    let account = keys(0x11);
    let relay = relay_url();
    for timestamp in [NOW - 600, NOW, NOW + 600] {
        validate_auth_event(
            &auth_event(&account, CHALLENGE, &relay, timestamp),
            &relay,
            CHALLENGE,
            NOW,
        )
        .unwrap();
    }
    for timestamp in [NOW - 601, NOW + 601] {
        assert_eq!(
            validate_auth_event(
                &auth_event(&account, CHALLENGE, &relay, timestamp),
                &relay,
                CHALLENGE,
                NOW,
            ),
            Err(AuthError::Stale)
        );
    }
}

#[test]
fn auth_error_debug_never_contains_challenge_or_event_content() {
    let account = keys(0x11);
    let secret = "challenge-must-not-leak";
    let event = auth_event(&account, secret, &relay_url(), NOW);
    let error = validate_auth_event(&event, &relay_url(), "different", NOW).unwrap_err();
    let debug = format!("{error:?}");

    assert!(!debug.contains(secret));
}

#![cfg(not(target_arch = "wasm32"))]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cgka_engine::key_package_metadata;
use cgka_traits::{KeyPackage, group::ProtocolProfile};
use marmot_wasm_probe::{MarmotProbe, error::ProbeError};
use nostr::{Event, JsonUtil, Keys};
use serde_json::Value;

const ALICE_SECRET: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const BOB_SECRET: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const RELAY: &str = "ws://deaddrop.invalid";

#[tokio::test]
async fn current_profile_two_party_flow_survives_restart() {
    let mut alice = MarmotProbe::create(ALICE_SECRET).unwrap();
    let mut bob = MarmotProbe::create(BOB_SECRET).unwrap();

    let key_package_json = bob.create_key_package(RELAY, 1_700_000_000).await.unwrap();
    let key_package_event = response_event(&key_package_json);
    assert_eq!(key_package_event.kind.as_u16(), 30_443);
    assert!(key_package_event.verify().is_ok());
    let key_package = KeyPackage::new(
        BASE64_STANDARD
            .decode(key_package_event.content.as_bytes())
            .unwrap(),
    )
    .with_protocol_profile(ProtocolProfile::Current);
    let key_package_metadata = key_package_metadata(&key_package).unwrap();
    assert_eq!(
        key_package_metadata.protocol_profile,
        ProtocolProfile::Current
    );
    assert_eq!(
        key_package_metadata.credential_identity_hex,
        key_package_event.pubkey.to_hex()
    );

    let group_h_hex = hex::encode(rand::random::<[u8; 32]>());
    let conversation_json = alice
        .create_conversation(&key_package_json, &group_h_hex)
        .await
        .unwrap();
    let conversation: Value = serde_json::from_str(&conversation_json).unwrap();
    let group_id_hex = conversation["group_id"].as_str().unwrap().to_owned();
    let welcome_event = value_event(&conversation["welcome"]);
    assert_eq!(welcome_event.kind.as_u16(), 1059);
    assert_ne!(
        welcome_event.pubkey,
        Keys::parse(ALICE_SECRET).unwrap().public_key()
    );

    bob.join_welcome(&welcome_event.as_json()).await.unwrap();

    let chat_json = alice
        .send_chat(
            &group_id_hex,
            "hello from a disposable sender",
            1_700_000_001,
        )
        .await
        .unwrap();
    let group_event = response_event(&chat_json);
    assert_eq!(group_event.kind.as_u16(), 445);
    assert_ne!(
        group_event.pubkey,
        Keys::parse(ALICE_SECRET).unwrap().public_key()
    );
    assert_eq!(
        group_event
            .tags
            .find(nostr::TagKind::custom("h"))
            .unwrap()
            .content(),
        Some(group_h_hex.as_str())
    );

    let received = bob.ingest(&group_event.as_json()).await.unwrap();
    assert_chat(&received, "hello from a disposable sender");

    let alice_state = alice.export_state().unwrap();
    let bob_state = bob.export_state().unwrap();
    drop(alice);
    drop(bob);
    let mut alice = MarmotProbe::from_state(&alice_state).unwrap();
    let mut bob = MarmotProbe::from_state(&bob_state).unwrap();

    let reply_json = bob
        .send_chat(&group_id_hex, "reply after restart", 1_700_000_002)
        .await
        .unwrap();
    let reply_event = response_event(&reply_json);
    let received = alice.ingest(&reply_event.as_json()).await.unwrap();
    assert_chat(&received, "reply after restart");
}

fn response_event(response: &str) -> Event {
    let value: Value = serde_json::from_str(response).unwrap();
    value_event(&value["event"])
}

fn value_event(value: &Value) -> Event {
    Event::from_json(serde_json::to_string(value).unwrap()).unwrap()
}

fn assert_chat(response: &str, expected: &str) {
    let value: Value = serde_json::from_str(response).unwrap();
    let message = &value["messages"][0];
    assert_eq!(message["kind"], 9);
    assert_eq!(message["content"], expected);
}

#[test]
fn state_import_rejects_oversized_input_before_deserialization() {
    assert!(matches!(
        MarmotProbe::from_state(&vec![0_u8; 17 * 1024 * 1024]),
        Err(ProbeError::SnapshotTooLarge)
    ));
}

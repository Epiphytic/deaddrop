#![cfg(target_arch = "wasm32")]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use marmot_wasm_probe::WasmMarmotProbe;
use serde_json::Value;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const ALICE_SECRET: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const BOB_SECRET: &str = "0202020202020202020202020202020202020202020202020202020202020202";

#[wasm_bindgen_test]
async fn current_profile_two_party_flow_runs_after_browser_restart() {
    consumes_native_fixture_after_browser_restore().await;

    let mut alice = WasmMarmotProbe::create(ALICE_SECRET).unwrap();
    let mut bob = WasmMarmotProbe::create(BOB_SECRET).unwrap();
    let key_package = bob
        .create_key_package("ws://deaddrop.invalid", 1_700_000_000)
        .await
        .unwrap();
    let key_package_value: Value = serde_json::from_str(&key_package).unwrap();
    assert_eq!(key_package_value["event"]["kind"], 30_443);

    let group_h = hex::encode([7_u8; 32]);
    let conversation = alice
        .create_conversation(&key_package, &group_h)
        .await
        .unwrap();
    let conversation: Value = serde_json::from_str(&conversation).unwrap();
    let group_id = conversation["group_id"].as_str().unwrap().to_owned();
    assert_eq!(conversation["welcome"]["kind"], 1059);
    bob.join_welcome(&serde_json::to_string(&conversation["welcome"]).unwrap())
        .await
        .unwrap();

    let alice_state = alice.export_state().unwrap();
    let bob_state = bob.export_state().unwrap();
    drop(alice);
    drop(bob);
    let mut alice = WasmMarmotProbe::from_state(&alice_state).unwrap();
    let mut bob = WasmMarmotProbe::from_state(&bob_state).unwrap();

    let sent = alice
        .send_chat(&group_id, "hello from browser wasm", 1_700_000_001)
        .await
        .unwrap();
    let sent: Value = serde_json::from_str(&sent).unwrap();
    assert_eq!(sent["event"]["kind"], 445);
    assert_eq!(sent["event"]["tags"][0][1], group_h);
    let received = bob
        .ingest(&serde_json::to_string(&sent["event"]).unwrap())
        .await
        .unwrap();
    let received: Value = serde_json::from_str(&received).unwrap();
    assert_eq!(received["messages"][0]["kind"], 9);
    assert_eq!(
        received["messages"][0]["content"],
        "hello from browser wasm"
    );
}

async fn consumes_native_fixture_after_browser_restore() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../artifacts/feasibility/marmot-native-fixture.json"
    ))
    .unwrap();
    assert_eq!(fixture["test_keys_only"], true);
    assert_eq!(fixture["profile"], "current");
    assert_eq!(
        fixture["mdk_rev"],
        "4981e591bd9399fdad6d5bf62ce6eafa70da7d0b"
    );
    assert_eq!(
        fixture["openmls_rev"],
        "59e7d3b27a7e95237879dd5478de1fd90eff7ada"
    );
    assert_eq!(fixture["key_package_event"]["kind"], 30_443);
    assert_eq!(fixture["welcome_event"]["kind"], 1059);
    assert_eq!(fixture["group_event"]["kind"], 445);
    assert_eq!(fixture["group_event"]["tags"][0][1], fixture["group_h"]);
    let state = BASE64_STANDARD
        .decode(fixture["bob_state_base64"].as_str().unwrap())
        .unwrap();
    let mut bob = WasmMarmotProbe::from_state(&state).unwrap();
    let joined = bob
        .join_welcome(&serde_json::to_string(&fixture["welcome_event"]).unwrap())
        .await
        .unwrap();
    let joined: Value = serde_json::from_str(&joined).unwrap();
    assert_eq!(joined["group_id"], fixture["group_id"]);
    let received = bob
        .ingest(&serde_json::to_string(&fixture["group_event"]).unwrap())
        .await
        .unwrap();
    let received: Value = serde_json::from_str(&received).unwrap();
    assert_eq!(received["messages"][0]["kind"], 9);
    assert_eq!(received["messages"][0]["content"], fixture["plaintext"]);
}

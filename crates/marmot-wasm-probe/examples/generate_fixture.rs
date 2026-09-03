#[cfg(not(target_arch = "wasm32"))]
use std::{env, fs, path::Path};

#[cfg(not(target_arch = "wasm32"))]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
#[cfg(not(target_arch = "wasm32"))]
use marmot_wasm_probe::MarmotProbe;
#[cfg(not(target_arch = "wasm32"))]
use serde_json::{Value, json};

#[cfg(not(target_arch = "wasm32"))]
const ALICE_SECRET: &str = "0101010101010101010101010101010101010101010101010101010101010101";
#[cfg(not(target_arch = "wasm32"))]
const BOB_SECRET: &str = "0202020202020202020202020202020202020202020202020202020202020202";

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    let mut args = env::args().skip(1);
    let output = args.next().expect("one fixture output path is required");
    assert!(args.next().is_none(), "exactly one output path is required");
    let output = Path::new(&output);
    let allowed = Path::new("artifacts/feasibility");
    assert!(
        output.parent() == Some(allowed) && output.extension().is_some_and(|value| value == "json"),
        "fixture output must be a JSON file under artifacts/feasibility/"
    );

    let mut alice = MarmotProbe::create(ALICE_SECRET).expect("Alice probe");
    let mut bob = MarmotProbe::create(BOB_SECRET).expect("Bob probe");
    let key_package = bob
        .create_key_package("ws://deaddrop.invalid", 1_700_000_000)
        .await
        .expect("Bob KeyPackage");
    let bob_state = bob.export_state().expect("Bob pre-Welcome state");
    let group_h = hex::encode([7_u8; 32]);
    let conversation = alice
        .create_conversation(&key_package, &group_h)
        .await
        .expect("Alice conversation");
    let conversation: Value = serde_json::from_str(&conversation).expect("conversation JSON");
    let group_id = conversation["group_id"].as_str().expect("group id");
    let sent = alice
        .send_chat(group_id, "native fixture plaintext", 1_700_000_001)
        .await
        .expect("Alice message");
    let sent: Value = serde_json::from_str(&sent).expect("sent JSON");
    let key_package: Value = serde_json::from_str(&key_package).expect("KeyPackage JSON");
    let fixture = json!({
        "test_keys_only": true,
        "generation_model": "fixed-input checked-in artifact; cryptographic bytes use fresh system entropy",
        "profile": "current",
        "mdk_rev": "4981e591bd9399fdad6d5bf62ce6eafa70da7d0b",
        "openmls_rev": "59e7d3b27a7e95237879dd5478de1fd90eff7ada",
        "group_id": group_id,
        "group_h": group_h,
        "plaintext": "native fixture plaintext",
        "bob_state_base64": BASE64_STANDARD.encode(bob_state),
        "key_package_event": key_package["event"],
        "welcome_event": conversation["welcome"],
        "group_event": sent["event"],
    });
    let encoded = serde_jcs::to_vec(&fixture).expect("RFC 8785 canonical fixture JSON");
    fs::create_dir_all(allowed).expect("fixture directory");
    let temporary = output.with_extension("json.tmp");
    fs::write(&temporary, encoded).expect("write temporary fixture");
    fs::rename(&temporary, output).expect("atomically install fixture");
}

#[cfg(target_arch = "wasm32")]
fn main() {}

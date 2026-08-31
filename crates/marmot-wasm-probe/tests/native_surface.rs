use marmot_wasm_probe::probe_build_info;

#[test]
fn reports_pinned_current_profile_surface() {
    let info: serde_json::Value = serde_json::from_str(&probe_build_info()).unwrap();
    assert_eq!(info["mdk_rev"], "876bdf3c408df0658c158da6a6521745cd0abde5");
    assert_eq!(info["profile"], "current");
    assert_eq!(info["kinds"], serde_json::json!([9, 445, 1059, 30443]));
}

use onion_probe::{ConfigError, OnionProbeConfig, StartupRecord, prepare_state_dir};

#[test]
fn production_has_no_clearnet_listener() {
    let cfg = OnionProbeConfig::production("/tmp/deaddrop-onion-probe".into());

    assert_eq!(cfg.virtual_port, 80);
    assert_eq!(cfg.clearnet_bind, None);
    assert_eq!(cfg.nickname, "deaddrop-feasibility");
}

#[test]
fn state_directory_is_required() {
    assert_eq!(
        OnionProbeConfig::try_new(None),
        Err(ConfigError::MissingStateDirectory)
    );
}

#[test]
fn startup_record_is_one_json_line_without_key_material() {
    let record = StartupRecord {
        onion_url: "http://example.onion".to_owned(),
        state_dir: "/var/lib/deaddrop/tor".into(),
    };

    let json = serde_json::to_string(&record).expect("startup record should serialize");

    assert!(!json.contains('\n'));
    assert_eq!(
        serde_json::from_str::<StartupRecord>(&json).expect("startup record should deserialize"),
        record
    );
    assert!(!json.contains("private"));
    assert!(!json.contains("secret"));
}

#[cfg(unix)]
#[test]
fn tor_state_directory_is_restricted_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().expect("temporary parent should be created");
    let state_dir = parent.path().join("tor-state");
    prepare_state_dir(&state_dir).expect("state directory should be prepared");

    let mode = std::fs::metadata(state_dir)
        .expect("state directory metadata should be readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

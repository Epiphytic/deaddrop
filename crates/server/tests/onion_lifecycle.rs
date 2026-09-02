use std::{
    fs,
    process::Command,
    sync::{Mutex, MutexGuard},
};

use deaddrop_server::{
    onion::StartupRecord,
    state::{IdentityState, StateDirectory, StateError},
};
use tempfile::TempDir;

const ADDRESS_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
const ADDRESS_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion";
static PROCESS_SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn private_temp() -> TempDir {
    TempDir::new_in(std::env::current_dir().unwrap()).unwrap()
}

fn process_spawn_lock() -> MutexGuard<'static, ()> {
    PROCESS_SPAWN_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

#[test]
fn missing_directory_is_created_privately_and_locked_exclusively() {
    let _process_spawn_lock = process_spawn_lock();
    let temp = private_temp();
    let data_dir = temp.path().join("private/relay");
    let first = StateDirectory::acquire(&data_dir).unwrap();

    assert_eq!(first.identity_state(), IdentityState::Fresh);
    assert_eq!(first.tor_dir(), data_dir.join("tor"));
    assert_eq!(first.database_path(), data_dir.join("relay.sqlite3"));
    assert!(matches!(
        StateDirectory::acquire(&data_dir),
        Err(StateError::AlreadyRunning)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(data_dir.join(".deaddrop.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    drop(first);
    StateDirectory::acquire(&data_dir).expect("dropping the owner must release the lock");
}

#[test]
fn parent_traversal_is_rejected_before_creating_any_directory() {
    let temp = private_temp();
    let requested = temp.path().join("new/../relay");

    assert!(matches!(
        StateDirectory::acquire(&requested),
        Err(StateError::ParentTraversal)
    ));
    assert!(!temp.path().join("new").exists());
    assert!(!temp.path().join("relay").exists());
}

#[test]
fn a_non_directory_state_path_is_rejected() {
    let temp = private_temp();
    let state_path = temp.path().join("state");
    fs::write(&state_path, b"not a directory").unwrap();

    assert!(matches!(
        StateDirectory::acquire(&state_path),
        Err(StateError::NotDirectory)
    ));
}

#[cfg(unix)]
#[test]
fn symlinked_path_components_are_rejected() {
    use std::os::unix::fs::symlink;

    let temp = private_temp();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = temp.path().join("link");
    symlink(&real, &link).unwrap();

    assert!(matches!(
        StateDirectory::acquire(link.join("relay")),
        Err(StateError::Symlink)
    ));
    assert!(!real.join("relay").exists());
}

#[cfg(unix)]
#[test]
fn accessible_existing_state_directory_is_rejected_without_repair() {
    use std::os::unix::fs::PermissionsExt;

    let temp = private_temp();
    let data_dir = temp.path().join("state");
    fs::create_dir(&data_dir).unwrap();
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o750)).unwrap();

    assert!(matches!(
        StateDirectory::acquire(&data_dir),
        Err(StateError::AccessiblePermissions)
    ));
    assert_eq!(
        fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert!(!data_dir.join(".deaddrop.lock").exists());
}

#[test]
fn initialization_evidence_without_a_manifest_fails_closed() {
    for evidence in ["relay.sqlite3", "tor", "unexpected"] {
        let temp = private_temp();
        let data_dir = temp.path().join("state");
        fs::create_dir(&data_dir).unwrap();
        set_private_directory(&data_dir);
        let path = data_dir.join(evidence);
        if evidence == "tor" {
            fs::create_dir(path).unwrap();
        } else {
            fs::write(path, b"evidence").unwrap();
        }

        assert!(matches!(
            StateDirectory::acquire(&data_dir),
            Err(StateError::IncompleteIdentity)
        ));
    }
}

#[test]
fn malformed_or_invalid_manifest_fails_closed() {
    for contents in [
        b"not json".as_slice(),
        br#"{"version":2,"onion_address":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"}"#,
        br#"{"version":1,"onion_address":"not-an-onion"}"#,
    ] {
        let temp = private_temp();
        let data_dir = temp.path().join("state");
        fs::create_dir(&data_dir).unwrap();
        set_private_directory(&data_dir);
        let manifest = data_dir.join("identity.json");
        fs::write(&manifest, contents).unwrap();
        set_private_file(&manifest);

        assert!(matches!(
            StateDirectory::acquire(&data_dir),
            Err(StateError::InvalidManifest)
        ));
    }
}

#[cfg(unix)]
#[test]
fn resume_rejects_a_symlinked_tor_state_before_launch() {
    use std::os::unix::fs::symlink;

    let temp = private_temp();
    let data_dir = temp.path().join("state");
    persist_manifest(&data_dir);
    let target = temp.path().join("external-tor");
    fs::create_dir(&target).unwrap();
    symlink(&target, data_dir.join("tor")).unwrap();

    assert!(matches!(
        StateDirectory::acquire(&data_dir),
        Err(StateError::Symlink)
    ));
}

#[cfg(unix)]
#[test]
fn resume_rejects_a_symlinked_relay_database_before_open() {
    use std::os::unix::fs::symlink;

    let temp = private_temp();
    let data_dir = temp.path().join("state");
    persist_manifest(&data_dir);
    let target = temp.path().join("external.sqlite3");
    fs::write(&target, b"external database").unwrap();
    symlink(&target, data_dir.join("relay.sqlite3")).unwrap();

    assert!(matches!(
        StateDirectory::acquire(&data_dir),
        Err(StateError::Symlink)
    ));
}

#[test]
fn durable_manifest_transitions_fresh_state_to_matching_resume() {
    let temp = private_temp();
    let data_dir = temp.path().join("state");
    let mut fresh = StateDirectory::acquire(&data_dir).unwrap();

    fresh.validate_or_record_identity(ADDRESS_A).unwrap();
    assert_eq!(fresh.identity_state(), IdentityState::Resume);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(data_dir.join("identity.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    drop(fresh);
    let mut resumed = StateDirectory::acquire(&data_dir).unwrap();
    assert_eq!(resumed.identity_state(), IdentityState::Resume);
    resumed.validate_or_record_identity(ADDRESS_A).unwrap();
    assert!(matches!(
        resumed.validate_or_record_identity(ADDRESS_B),
        Err(StateError::IdentityMismatch)
    ));
}

#[test]
fn startup_record_contains_only_canonical_public_urls() {
    let record = StartupRecord::from_onion_address(ADDRESS_A);
    let value = serde_json::to_value(record).unwrap();

    assert_eq!(
        value,
        serde_json::json!({
            "onion_url": format!("http://{ADDRESS_A}"),
            "relay_url": format!("ws://{ADDRESS_A}/relay"),
        })
    );
}

#[test]
fn locked_relay_startup_fails_without_stdout_or_debug_mode_diagnostics() {
    let _process_spawn_lock = process_spawn_lock();
    let temp = private_temp();
    let data_dir = temp.path().join("state");
    let _owner = StateDirectory::acquire(&data_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_deaddrop"))
        .args(["relay", "--data-dir"])
        .arg(&data_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("\"event\":\"relay_failed\""));
    assert!(!stderr.contains("debug_server_failed"));
}

fn set_private_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn set_private_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn persist_manifest(data_dir: &std::path::Path) {
    let mut state = StateDirectory::acquire(data_dir).unwrap();
    state.validate_or_record_identity(ADDRESS_A).unwrap();
}

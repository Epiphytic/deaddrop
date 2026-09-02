use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const LOCK_FILE: &str = ".deaddrop.lock";
const MANIFEST_FILE: &str = "identity.json";
const MANIFEST_TEMP_FILE: &str = ".identity.json.tmp";
const MANIFEST_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityState {
    Fresh,
    Resume,
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("the relay data directory path is empty")]
    EmptyPath,
    #[error("the relay data directory may not contain parent traversal")]
    ParentTraversal,
    #[error("a relay data directory path component is a symbolic link")]
    Symlink,
    #[error("the relay data path is not a directory")]
    NotDirectory,
    #[error("the relay data directory must not be accessible by group or other users")]
    AccessiblePermissions,
    #[error("another relay process already owns this data directory")]
    AlreadyRunning,
    #[error("the relay identity is incomplete or lost")]
    IncompleteIdentity,
    #[error("the relay identity manifest is invalid")]
    InvalidManifest,
    #[error("the launched onion identity does not match the persisted manifest")]
    IdentityMismatch,
    #[error("failed to access relay state: {0}")]
    Io(#[source] io::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityManifest {
    version: u32,
    onion_address: String,
}

/// Exclusive owner of one relay data directory and its persisted identity.
///
/// The lock file remains open and locked until this value is dropped.
pub struct StateDirectory {
    data_dir: PathBuf,
    identity_state: IdentityState,
    manifest_address: Option<String>,
    _lock: File,
}

impl StateDirectory {
    pub fn acquire(data_dir: impl AsRef<Path>) -> Result<Self, StateError> {
        let data_dir = data_dir.as_ref();
        validate_lexical_path(data_dir)?;
        inspect_existing_components(data_dir)?;
        create_private_directory(data_dir)?;
        validate_directory(data_dir)?;

        let lock_path = data_dir.join(LOCK_FILE);
        reject_existing_symlink(&lock_path)?;
        let lock = open_private_lock(&lock_path)?;
        FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                StateError::AlreadyRunning
            } else {
                StateError::Io(error)
            }
        })?;
        restrict_file_to_owner(&lock)?;
        inspect_existing_components(&data_dir.join("tor"))?;
        inspect_existing_components(&data_dir.join("relay.sqlite3"))?;

        let (identity_state, manifest_address) = classify_identity(data_dir)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            identity_state,
            manifest_address,
            _lock: lock,
        })
    }

    pub fn identity_state(&self) -> IdentityState {
        self.identity_state
    }

    pub fn tor_dir(&self) -> PathBuf {
        self.data_dir.join("tor")
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("relay.sqlite3")
    }

    pub fn validate_or_record_identity(&mut self, onion_address: &str) -> Result<(), StateError> {
        if !valid_onion_address(onion_address) {
            return Err(StateError::InvalidManifest);
        }
        match (&self.identity_state, &self.manifest_address) {
            (IdentityState::Fresh, None) => {
                write_manifest(&self.data_dir, onion_address)?;
                self.identity_state = IdentityState::Resume;
                self.manifest_address = Some(onion_address.to_owned());
                Ok(())
            }
            (IdentityState::Resume, Some(expected)) if expected == onion_address => Ok(()),
            (IdentityState::Resume, Some(_)) => Err(StateError::IdentityMismatch),
            _ => Err(StateError::InvalidManifest),
        }
    }
}

fn validate_lexical_path(path: &Path) -> Result<(), StateError> {
    if path.as_os_str().is_empty() {
        return Err(StateError::EmptyPath);
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(StateError::ParentTraversal);
    }
    Ok(())
}

fn inspect_existing_components(path: &Path) -> Result<(), StateError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(StateError::Symlink),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(StateError::Io(error)),
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), StateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() => return Err(StateError::NotDirectory),
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(StateError::Io(error)),
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(StateError::Io)
}

fn validate_directory(path: &Path) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(path).map_err(StateError::Io)?;
    if metadata.file_type().is_symlink() {
        return Err(StateError::Symlink);
    }
    if !metadata.is_dir() {
        return Err(StateError::NotDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StateError::AccessiblePermissions);
        }
    }
    Ok(())
}

fn reject_existing_symlink(path: &Path) -> Result<(), StateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StateError::Symlink),
        Ok(metadata) if !metadata.is_file() => Err(StateError::IncompleteIdentity),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StateError::Io(error)),
    }
}

fn open_private_lock(path: &Path) -> Result<File, StateError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(StateError::Io)
}

fn restrict_file_to_owner(file: &File) -> Result<(), StateError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(StateError::Io)?;
    }
    Ok(())
}

fn classify_identity(path: &Path) -> Result<(IdentityState, Option<String>), StateError> {
    let manifest_path = path.join(MANIFEST_FILE);
    match fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_MANIFEST_BYTES
            {
                return Err(StateError::InvalidManifest);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(StateError::InvalidManifest);
                }
            }
            let bytes = fs::read(&manifest_path).map_err(StateError::Io)?;
            let manifest: IdentityManifest =
                serde_json::from_slice(&bytes).map_err(|_| StateError::InvalidManifest)?;
            if manifest.version != MANIFEST_VERSION || !valid_onion_address(&manifest.onion_address)
            {
                return Err(StateError::InvalidManifest);
            }
            Ok((IdentityState::Resume, Some(manifest.onion_address)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let entries = fs::read_dir(path).map_err(StateError::Io)?;
            let has_evidence = has_initialization_evidence(entries)?;
            if has_evidence {
                Err(StateError::IncompleteIdentity)
            } else {
                Ok((IdentityState::Fresh, None))
            }
        }
        Err(error) => Err(StateError::Io(error)),
    }
}

fn has_initialization_evidence(
    entries: impl IntoIterator<Item = io::Result<fs::DirEntry>>,
) -> Result<bool, StateError> {
    for entry in entries {
        if entry.map_err(StateError::Io)?.file_name() != LOCK_FILE {
            return Ok(true);
        }
    }
    Ok(false)
}

fn valid_onion_address(address: &str) -> bool {
    let Some(label) = address.strip_suffix(".onion") else {
        return false;
    };
    label.len() == 56
        && label
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
}

fn write_manifest(path: &Path, onion_address: &str) -> Result<(), StateError> {
    let manifest = IdentityManifest {
        version: MANIFEST_VERSION,
        onion_address: onion_address.to_owned(),
    };
    let mut bytes = serde_json::to_vec(&manifest).map_err(|_| StateError::InvalidManifest)?;
    bytes.push(b'\n');

    let temporary_path = path.join(MANIFEST_TEMP_FILE);
    reject_existing_symlink(&temporary_path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temporary = options.open(&temporary_path).map_err(StateError::Io)?;
    let result = (|| {
        temporary.write_all(&bytes).map_err(StateError::Io)?;
        temporary.sync_all().map_err(StateError::Io)?;
        drop(temporary);
        fs::rename(&temporary_path, path.join(MANIFEST_FILE)).map_err(StateError::Io)?;
        sync_directory(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(StateError::Io)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use super::{StateError, has_initialization_evidence};

    #[test]
    fn directory_entry_error_is_not_discarded_as_empty_state() {
        let entries = std::iter::once(Err::<fs::DirEntry, _>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected directory entry failure",
        )));

        let result = has_initialization_evidence(entries);

        assert!(matches!(
            result,
            Err(StateError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
    }
}

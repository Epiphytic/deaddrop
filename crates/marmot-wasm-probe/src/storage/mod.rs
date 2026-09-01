mod groups;
mod kv;
mod lifecycle;
mod messages;
mod outbound;

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use cgka_traits::storage::{StorageError, StorageResult};
use openmls_memory_storage::MemoryStorage;
use parking_lot::ReentrantMutex;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    error::ProbeError,
    snapshot::{MAX_SNAPSHOT_BYTES, SnapshotV1},
};

/// Serializable in-memory storage for the single-owner browser Worker probe.
///
/// Application-side operations are coordinated for transactional rollback.
/// OpenMLS exposes its in-memory backend by shared reference, so callers must
/// keep the complete engine and this store on one Worker rather than issuing
/// concurrent native-thread writes through [`Self::mls_storage`]. Production
/// browser persistence will replace this probe with a Worker-owned OPFS store.
#[derive(Debug, Default)]
pub struct WasmStorage {
    coordinator: ReentrantMutex<()>,
    app_entries: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
    openmls: MemoryStorage,
    transaction_active: AtomicBool,
}

impl WasmStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn export(&self) -> Result<Vec<u8>, ProbeError> {
        self.coordinated(|| {
            let app_entries_guard = self
                .app_entries
                .read()
                .map_err(|_| ProbeError::Serialization)?;
            let openmls_entries_guard = self
                .openmls
                .values
                .read()
                .map_err(|_| ProbeError::Serialization)?;
            let raw_bytes = app_entries_guard
                .iter()
                .chain(openmls_entries_guard.iter())
                .try_fold(0_usize, |total, (key, value)| {
                    total.checked_add(key.len())?.checked_add(value.len())
                })
                .ok_or(ProbeError::SnapshotTooLarge)?;
            if raw_bytes > MAX_SNAPSHOT_BYTES {
                return Err(ProbeError::SnapshotTooLarge);
            }
            let app_entries = app_entries_guard.clone();
            let openmls_entries = openmls_entries_guard
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();

            let encoded = postcard::to_allocvec(&SnapshotV1::new(app_entries, openmls_entries))
                .map_err(|_| ProbeError::Serialization)?;
            if encoded.len() > MAX_SNAPSHOT_BYTES {
                return Err(ProbeError::SnapshotTooLarge);
            }
            Ok(encoded)
        })
    }

    pub fn import(encoded: &[u8]) -> Result<Self, ProbeError> {
        if encoded.len() > MAX_SNAPSHOT_BYTES {
            return Err(ProbeError::SnapshotTooLarge);
        }
        let (snapshot, remainder): (SnapshotV1, &[u8]) =
            postcard::take_from_bytes(encoded).map_err(|_| ProbeError::Serialization)?;
        if !remainder.is_empty() {
            return Err(ProbeError::Serialization);
        }
        snapshot.validate()?;

        Ok(Self {
            coordinator: ReentrantMutex::new(()),
            app_entries: RwLock::new(snapshot.app_entries),
            openmls: MemoryStorage {
                values: RwLock::new(
                    snapshot
                        .openmls_entries
                        .into_iter()
                        .collect::<HashMap<_, _>>(),
                ),
            },
            transaction_active: AtomicBool::new(false),
        })
    }

    pub fn with_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        let _coordinator = self.coordinator.lock();
        if self
            .transaction_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(StorageError::Backend(ProbeError::NestedTransaction.to_string()).into());
        }
        let _transaction_flag = TransactionFlagGuard(&self.transaction_active);

        let app_before = self
            .app_entries
            .read()
            .map_err(|_| StorageError::Backend("application storage lock poisoned".into()))?
            .clone();
        let openmls_before = self
            .openmls
            .values
            .read()
            .map_err(|_| StorageError::Backend("OpenMLS storage lock poisoned".into()))?
            .clone();

        let result = operation(self);
        if result.is_err() {
            *self
                .app_entries
                .write()
                .map_err(|_| StorageError::Backend("application storage lock poisoned".into()))? =
                app_before;
            *self
                .openmls
                .values
                .write()
                .map_err(|_| StorageError::Backend("OpenMLS storage lock poisoned".into()))? =
                openmls_before;
        }
        result
    }

    pub(crate) fn coordinated<T>(&self, operation: impl FnOnce() -> T) -> T {
        let _guard = self.coordinator.lock();
        operation()
    }

    pub(crate) fn put<T: Serialize>(
        &self,
        namespace: &str,
        id: &[u8],
        value: &T,
    ) -> StorageResult<()> {
        self.coordinated(|| {
            let mut entries = self.write_app()?;
            kv::put_json(&mut entries, namespace, id, value)
        })
    }

    pub(crate) fn get<T: DeserializeOwned>(
        &self,
        namespace: &str,
        id: &[u8],
    ) -> StorageResult<Option<T>> {
        self.coordinated(|| {
            let entries = self.read_app()?;
            kv::get_json(&entries, namespace, id)
        })
    }

    pub(crate) fn scan<T: DeserializeOwned>(&self, namespace: &str) -> StorageResult<Vec<T>> {
        self.coordinated(|| {
            let entries = self.read_app()?;
            kv::scan_json(&entries, namespace)
        })
    }

    pub(crate) fn delete(&self, namespace: &str, id: &[u8]) -> StorageResult<()> {
        self.coordinated(|| {
            self.write_app()?.remove(&kv::key(namespace, id));
            Ok(())
        })
    }

    pub(crate) fn delete_prefix(&self, namespace: &str, id_prefix: &[u8]) -> StorageResult<()> {
        self.coordinated(|| {
            let prefix = kv::key(namespace, id_prefix);
            self.write_app()?
                .retain(|entry_key, _| !entry_key.starts_with(&prefix));
            Ok(())
        })
    }

    pub(crate) fn read_app(
        &self,
    ) -> StorageResult<std::sync::RwLockReadGuard<'_, BTreeMap<Vec<u8>, Vec<u8>>>> {
        self.app_entries
            .read()
            .map_err(|_| StorageError::Backend("application storage lock poisoned".into()))
    }

    pub(crate) fn write_app(
        &self,
    ) -> StorageResult<std::sync::RwLockWriteGuard<'_, BTreeMap<Vec<u8>, Vec<u8>>>> {
        self.app_entries
            .write()
            .map_err(|_| StorageError::Backend("application storage lock poisoned".into()))
    }

    pub(crate) fn openmls(&self) -> &MemoryStorage {
        &self.openmls
    }

    #[doc(hidden)]
    pub fn test_put_raw(&self, namespace: &str, key: &[u8], value: &[u8]) -> StorageResult<()> {
        self.coordinated(|| {
            self.app_entries
                .write()
                .map_err(|_| StorageError::Backend("application storage lock poisoned".into()))?
                .insert(kv::key(namespace, key), value.to_vec());
            Ok(())
        })
    }

    #[doc(hidden)]
    pub fn test_get_raw(&self, namespace: &str, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        self.coordinated(|| {
            Ok(self
                .app_entries
                .read()
                .map_err(|_| StorageError::Backend("application storage lock poisoned".into()))?
                .get(&kv::key(namespace, key))
                .cloned())
        })
    }
}

struct TransactionFlagGuard<'a>(&'a AtomicBool);

impl Drop for TransactionFlagGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(crate) fn composite(parts: &[&[u8]]) -> Vec<u8> {
    let total_len = parts.iter().map(|part| 4 + part.len()).sum();
    let mut encoded = Vec::with_capacity(total_len);
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u32).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    encoded
}

use cgka_traits::{
    convergence_pass::DurableConvergencePass,
    storage::{
        AccountDeviceSignerBinding, AccountDeviceSignerStorage, ConvergencePassStorage,
        DeferredPeelGeneration, DeferredPeelGenerationStorage, KeyPackageBundleStorage,
        StorageError, StorageProvider, StorageResult, StoredKeyPackageBundle, WelcomeStorage,
    },
    types::{Backend, GroupId, MemberId, MessageId},
    welcome::PendingWelcome,
};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::storage::CURRENT_VERSION;
use zeroize::Zeroizing;

use super::{WasmStorage, kv};

const WELCOME: &str = "welcome";
const CONVERGENCE_PASS: &str = "convergence-pass";
const DEFERRED_PEEL: &str = "deferred-peel";
const ACCOUNT_SIGNER: &str = "account-signer";
const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";

impl WelcomeStorage for WasmStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()> {
        self.put(WELCOME, welcome.message_id.as_slice(), welcome)
    }

    fn take_welcome(&self, id: &MessageId) -> StorageResult<PendingWelcome> {
        self.coordinated(|| {
            let mut entries = self.write_app()?;
            let key = kv::key(WELCOME, id.as_slice());
            let encoded = entries.get(&key).ok_or(StorageError::NotFound)?;
            let welcome = serde_json::from_slice(encoded)
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
            entries.remove(&key);
            Ok(welcome)
        })
    }

    fn list_welcomes(&self) -> StorageResult<Vec<PendingWelcome>> {
        let mut welcomes = self.scan::<PendingWelcome>(WELCOME)?;
        welcomes.sort_by(|left, right| left.message_id.as_slice().cmp(right.message_id.as_slice()));
        Ok(welcomes)
    }
}

impl ConvergencePassStorage for WasmStorage {
    fn convergence_pass(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DurableConvergencePass>> {
        self.get(CONVERGENCE_PASS, group_id.as_slice())
    }

    fn put_convergence_pass(&self, pass: &DurableConvergencePass) -> StorageResult<()> {
        self.put(CONVERGENCE_PASS, pass.group_id.as_slice(), pass)
    }

    fn list_convergence_passes(&self) -> StorageResult<Vec<DurableConvergencePass>> {
        let mut passes = self.scan::<DurableConvergencePass>(CONVERGENCE_PASS)?;
        passes.sort_by(|left, right| left.group_id.as_slice().cmp(right.group_id.as_slice()));
        Ok(passes)
    }

    fn delete_convergence_pass(&self, group_id: &GroupId) -> StorageResult<()> {
        self.delete(CONVERGENCE_PASS, group_id.as_slice())
    }
}

impl DeferredPeelGenerationStorage for WasmStorage {
    fn deferred_peel_generation(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DeferredPeelGeneration>> {
        self.get(DEFERRED_PEEL, group_id.as_slice())
    }

    fn put_deferred_peel_generation(
        &self,
        generation: &DeferredPeelGeneration,
    ) -> StorageResult<()> {
        self.put(DEFERRED_PEEL, generation.group_id.as_slice(), generation)
    }

    fn delete_deferred_peel_generation(&self, group_id: &GroupId) -> StorageResult<()> {
        self.delete(DEFERRED_PEEL, group_id.as_slice())
    }
}

impl AccountDeviceSignerStorage for WasmStorage {
    fn put_account_device_signer(&self, binding: &AccountDeviceSignerBinding) -> StorageResult<()> {
        self.put(ACCOUNT_SIGNER, binding.marmot_identity.as_slice(), binding)
    }

    fn account_device_signer(
        &self,
        marmot_identity: &MemberId,
    ) -> StorageResult<Option<AccountDeviceSignerBinding>> {
        self.get(ACCOUNT_SIGNER, marmot_identity.as_slice())
    }
}

impl KeyPackageBundleStorage for WasmStorage {
    fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>> {
        self.coordinated(|| {
            let version = CURRENT_VERSION.to_be_bytes();
            let values = self
                .openmls()
                .values
                .read()
                .map_err(|_| StorageError::Backend("OpenMLS storage lock poisoned".into()))?;
            let mut bundles = values
                .iter()
                .filter_map(|(key, value)| {
                    if key.starts_with(KEY_PACKAGE_LABEL)
                        && key.ends_with(&version)
                        && key.len() >= KEY_PACKAGE_LABEL.len() + version.len()
                    {
                        let storage_key =
                            key[KEY_PACKAGE_LABEL.len()..key.len() - version.len()].to_vec();
                        Some(StoredKeyPackageBundle {
                            storage_key,
                            value: Zeroizing::new(value.clone()),
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            bundles.sort_by(|left, right| left.storage_key.cmp(&right.storage_key));
            Ok(bundles)
        })
    }

    fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()> {
        self.coordinated(|| {
            let mut key = Vec::with_capacity(KEY_PACKAGE_LABEL.len() + storage_key.len() + 2);
            key.extend_from_slice(KEY_PACKAGE_LABEL);
            key.extend_from_slice(storage_key);
            key.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
            self.openmls()
                .values
                .write()
                .map_err(|_| StorageError::Backend("OpenMLS storage lock poisoned".into()))?
                .remove(&key);
            Ok(())
        })
    }
}

impl StorageProvider for WasmStorage {
    type Mls = MemoryStorage;

    fn mls_storage(&self) -> &Self::Mls {
        self.openmls()
    }

    fn with_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        Self: Sized,
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        WasmStorage::with_transaction(self, operation)
    }

    fn backend(&self) -> Backend {
        // Compatibility sentinel: the pinned MDK enum does not yet expose Memory.
        Backend::Sqlite
    }
}

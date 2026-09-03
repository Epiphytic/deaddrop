use std::collections::BTreeMap;

use cgka_traits::storage::{StorageError, StorageResult};
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn key(namespace: &str, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(namespace.len() + 1 + id.len());
    key.extend_from_slice(namespace.as_bytes());
    key.push(0);
    key.extend_from_slice(id);
    key
}

pub(crate) fn put_json<T: Serialize>(
    entries: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    namespace: &str,
    id: &[u8],
    value: &T,
) -> StorageResult<()> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| StorageError::Serialization(error.to_string()))?;
    entries.insert(key(namespace, id), encoded);
    Ok(())
}

pub(crate) fn get_json<T: DeserializeOwned>(
    entries: &BTreeMap<Vec<u8>, Vec<u8>>,
    namespace: &str,
    id: &[u8],
) -> StorageResult<Option<T>> {
    entries
        .get(&key(namespace, id))
        .map(|encoded| {
            serde_json::from_slice(encoded)
                .map_err(|error| StorageError::Serialization(error.to_string()))
        })
        .transpose()
}

pub(crate) fn scan_json<T: DeserializeOwned>(
    entries: &BTreeMap<Vec<u8>, Vec<u8>>,
    namespace: &str,
) -> StorageResult<Vec<T>> {
    let prefix = key(namespace, b"");
    entries
        .range(prefix.clone()..)
        .take_while(|(entry_key, _)| entry_key.starts_with(&prefix))
        .map(|(_, encoded)| {
            serde_json::from_slice(encoded)
                .map_err(|error| StorageError::Serialization(error.to_string()))
        })
        .collect()
}

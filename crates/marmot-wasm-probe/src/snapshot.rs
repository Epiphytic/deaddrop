use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ProbeError;

pub(crate) const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const SNAPSHOT_VERSION: u16 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SnapshotV1 {
    pub(crate) version: u16,
    pub(crate) app_entries: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(crate) openmls_entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl SnapshotV1 {
    pub(crate) fn new(
        app_entries: BTreeMap<Vec<u8>, Vec<u8>>,
        openmls_entries: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            app_entries,
            openmls_entries,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ProbeError> {
        if self.version != SNAPSHOT_VERSION {
            return Err(ProbeError::SnapshotVersion(self.version));
        }
        Ok(())
    }
}

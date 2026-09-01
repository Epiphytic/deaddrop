use std::collections::{BTreeMap, HashMap};

use cgka_traits::{
    OutboundFanout,
    engine::GroupEvent,
    message::{MessageRecord, MessageState},
    storage::{GroupStateCheckpointRef, GroupStorage, MessageStorage, StorageError, StorageResult},
    types::{EpochId, GroupId, MessageId},
};
use openmls::group::GroupId as OpenMlsGroupId;
use openmls_traits::storage::CURRENT_VERSION;
use serde::{Deserialize, Serialize};

use super::{WasmStorage, composite};

const MESSAGE: &str = "message";
const PENDING_EVENT: &str = "pending-event";
const DEDUP: &str = "dedup";
const SNAPSHOT: &str = "snapshot";
const CHECKPOINT: &str = "checkpoint";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredSnapshot {
    group_id: GroupId,
    name: String,
    #[serde(default)]
    scope: SnapshotScope,
    app_entries: Vec<(Vec<u8>, Vec<u8>)>,
    openmls_entries: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum SnapshotScope {
    #[default]
    Full,
    Canonical,
}

#[derive(Deserialize)]
struct GroupOwnedRecord {
    group_id: GroupId,
}

const OPENMLS_GROUP_LABELS: &[&[u8]] = &[
    b"Tree",
    b"GroupContext",
    b"ApplicationExportTree",
    b"InterimTranscriptHash",
    b"ConfirmationTag",
    b"MlsGroupJoinConfig",
    b"OwnLeafNodes",
    b"GroupState",
    b"QueuedProposal",
    b"ProposalQueueRefs",
    b"OwnLeafNodeIndex",
    b"EpochSecrets",
    b"EpochKeyPairs",
    b"ResumptionPsk",
    b"MessageSecrets",
];

fn split_app_key(key: &[u8]) -> Option<(&str, &[u8])> {
    let separator = key.iter().position(|byte| *byte == 0)?;
    let namespace = std::str::from_utf8(&key[..separator]).ok()?;
    Some((namespace, &key[separator + 1..]))
}

fn composite_starts_with(key: &[u8], first: &[u8]) -> bool {
    key.get(..4)
        .and_then(|length| length.try_into().ok())
        .map(u32::from_be_bytes)
        .is_some_and(|length| {
            length as usize == first.len() && key.get(4..4 + first.len()) == Some(first)
        })
}

fn app_entry_belongs_to_group(
    key: &[u8],
    value: &[u8],
    group_id: &GroupId,
    scope: SnapshotScope,
) -> bool {
    let Some((namespace, id)) = split_app_key(key) else {
        return false;
    };
    if scope == SnapshotScope::Canonical {
        return match namespace {
            "group" | "validation" => id == group_id.as_slice(),
            "member-capability" => composite_starts_with(id, group_id.as_slice()),
            _ => false,
        };
    }
    match namespace {
        "group" | "leave" | "disband-request" | "disband-tombstone" | "convergence-policy"
        | "convergence-pass" | "deferred-peel" | "validation" => id == group_id.as_slice(),
        "member-capability" | "disband-candidate" => composite_starts_with(id, group_id.as_slice()),
        "message" | "intent" | "welcome" | "route" => {
            serde_json::from_slice::<GroupOwnedRecord>(value)
                .is_ok_and(|record| record.group_id == *group_id)
        }
        "fanout" => serde_json::from_slice::<OutboundFanout>(value)
            .is_ok_and(|fanout| fanout.group_id() == Some(group_id)),
        "pending-event" => serde_json::from_slice::<GroupEvent>(value).is_ok_and(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, .. }
                    | GroupEvent::GroupJoined { group_id: event_group, .. }
                    if event_group == *group_id
            )
        }),
        "snapshot" | "checkpoint" | "dedup" | "feature" | "account-signer" => false,
        _ => false,
    }
}

fn openmls_entry_belongs_to_group(key: &[u8], group_id: &GroupId) -> bool {
    let version_len = std::mem::size_of::<u16>();
    let serialized_group_id =
        match serde_json::to_vec(&OpenMlsGroupId::from_slice(group_id.as_slice())) {
            Ok(group_id) => group_id,
            Err(_) => return false,
        };
    OPENMLS_GROUP_LABELS.iter().any(|label| {
        let Some(versioned_body) = key.strip_prefix(*label) else {
            return false;
        };
        let Some((body, version)) =
            versioned_body.split_at_checked(versioned_body.len().saturating_sub(version_len))
        else {
            return false;
        };
        if version != CURRENT_VERSION.to_be_bytes() {
            return false;
        }
        match *label {
            b"QueuedProposal" => {
                let mut prefix = Vec::with_capacity(serialized_group_id.len() + 2);
                prefix.push(b'[');
                prefix.extend_from_slice(&serialized_group_id);
                prefix.push(b',');
                body.starts_with(&prefix)
            }
            b"EpochKeyPairs" => body.starts_with(&serialized_group_id),
            _ => body == serialized_group_id,
        }
    })
}

fn pending_event_id(event: &GroupEvent) -> StorageResult<&MessageId> {
    match event {
        GroupEvent::MessageReceived { message_id, .. } => Ok(message_id),
        GroupEvent::GroupJoined { via_welcome, .. } => Ok(via_welcome),
        _ => Err(StorageError::Backend(
            "pending application outbox accepts only MessageReceived and GroupJoined events"
                .to_owned(),
        )),
    }
}

impl WasmStorage {
    fn capture_snapshot(
        &self,
        group_id: &GroupId,
        name: &str,
        scope: SnapshotScope,
    ) -> StorageResult<StoredSnapshot> {
        self.coordinated(|| {
            self.get_group(group_id)?;
            let app_entries = self
                .read_app()?
                .iter()
                .filter(|(key, value)| app_entry_belongs_to_group(key, value, group_id, scope))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect();
            let openmls_entries = self
                .openmls()
                .values
                .read()
                .map_err(|_| StorageError::Backend("OpenMLS storage lock poisoned".into()))?
                .iter()
                .filter(|(key, _)| openmls_entry_belongs_to_group(key, group_id))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect();
            Ok(StoredSnapshot {
                group_id: group_id.clone(),
                name: name.to_owned(),
                scope,
                app_entries,
                openmls_entries,
            })
        })
    }

    fn restore_snapshot(&self, snapshot: StoredSnapshot) -> StorageResult<()> {
        self.coordinated(|| {
            let group_id = snapshot.group_id;
            let scope = snapshot.scope;
            let mut app_entries = self.write_app()?;
            app_entries
                .retain(|key, value| !app_entry_belongs_to_group(key, value, &group_id, scope));
            app_entries.extend(snapshot.app_entries);
            drop(app_entries);

            let mut openmls_entries = self
                .openmls()
                .values
                .write()
                .map_err(|_| StorageError::Backend("OpenMLS storage lock poisoned".into()))?;
            openmls_entries.retain(|key, _| !openmls_entry_belongs_to_group(key, &group_id));
            openmls_entries.extend(
                snapshot
                    .openmls_entries
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
            );
            Ok(())
        })
    }
}

impl MessageStorage for WasmStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        self.put(MESSAGE, record.id.as_slice(), record)
    }

    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord> {
        self.get(MESSAGE, id.as_slice())?
            .ok_or(StorageError::NotFound)
    }

    fn delete_message(&self, id: &MessageId) -> StorageResult<()> {
        self.delete(MESSAGE, id.as_slice())
    }

    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()> {
        let mut message: MessageRecord = self.get_message(id)?;
        message.state = new_state;
        self.put_message(&message)
    }

    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        let mut messages = self
            .scan::<MessageRecord>(MESSAGE)?
            .into_iter()
            .filter(|message| &message.group_id == group_id && message.epoch >= at_or_after_epoch)
            .collect::<Vec<_>>();
        messages.sort_by(|left, right| {
            left.epoch
                .cmp(&right.epoch)
                .then(left.id.as_slice().cmp(right.id.as_slice()))
        });
        Ok(messages)
    }

    fn put_pending_application_event(&self, event: &GroupEvent) -> StorageResult<()> {
        self.put(PENDING_EVENT, pending_event_id(event)?.as_slice(), event)
    }

    fn list_pending_application_events(&self) -> StorageResult<Vec<GroupEvent>> {
        self.scan(PENDING_EVENT)
    }

    fn delete_pending_application_events(&self, ids: &[MessageId]) -> StorageResult<()> {
        for id in ids {
            self.delete(PENDING_EVENT, id.as_slice())?;
        }
        Ok(())
    }

    fn put_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<()> {
        self.put(DEDUP, id.as_slice(), &true)
    }

    fn has_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<bool> {
        Ok(self.get::<bool>(DEDUP, id.as_slice())?.unwrap_or(false))
    }

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.coordinated(|| {
            let snapshot = self.capture_snapshot(group_id, name, SnapshotScope::Full)?;
            self.put(
                SNAPSHOT,
                &composite(&[group_id.as_slice(), name.as_bytes()]),
                &snapshot,
            )
        })
    }

    fn list_group_snapshots(&self, group_id: &GroupId) -> StorageResult<Vec<String>> {
        let mut names = self
            .scan::<StoredSnapshot>(SNAPSHOT)?
            .into_iter()
            .filter(|snapshot| &snapshot.group_id == group_id)
            .map(|snapshot| snapshot.name)
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }

    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.coordinated(|| {
            let snapshot = self
                .get::<StoredSnapshot>(
                    SNAPSHOT,
                    &composite(&[group_id.as_slice(), name.as_bytes()]),
                )?
                .ok_or_else(|| StorageError::SnapshotMissing(name.to_owned()))?;
            self.restore_snapshot(snapshot)
        })
    }

    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.coordinated(|| {
            let key = composite(&[group_id.as_slice(), name.as_bytes()]);
            if self.get::<StoredSnapshot>(SNAPSHOT, &key)?.is_none() {
                return Err(StorageError::SnapshotMissing(name.to_owned()));
            }
            self.delete(SNAPSHOT, &key)
        })
    }

    fn create_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint: &GroupStateCheckpointRef,
    ) -> StorageResult<()> {
        self.coordinated(|| {
            let key = composite(&[group_id.as_slice(), checkpoint.id.as_bytes()]);
            let snapshot =
                self.capture_snapshot(group_id, &checkpoint.id, SnapshotScope::Canonical)?;
            if let Some(existing) =
                self.get::<(GroupStateCheckpointRef, StoredSnapshot)>(CHECKPOINT, &key)?
            {
                if existing.0 != *checkpoint || existing.1 != snapshot {
                    return Err(StorageError::AlreadyExists);
                }
                return Ok(());
            }
            self.put(CHECKPOINT, &key, &(checkpoint.clone(), snapshot))
        })
    }

    fn restore_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        self.coordinated(|| {
            let (_, snapshot) = self
                .get::<(GroupStateCheckpointRef, StoredSnapshot)>(
                    CHECKPOINT,
                    &composite(&[group_id.as_slice(), checkpoint_id.as_bytes()]),
                )?
                .ok_or_else(|| StorageError::SnapshotMissing(checkpoint_id.to_owned()))?;
            self.restore_snapshot(snapshot)
        })
    }

    fn list_group_state_checkpoints(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<GroupStateCheckpointRef>> {
        let mut checkpoints = self
            .scan::<(GroupStateCheckpointRef, StoredSnapshot)>(CHECKPOINT)?
            .into_iter()
            .filter(|(_, snapshot)| &snapshot.group_id == group_id)
            .map(|(checkpoint, _)| checkpoint)
            .collect::<Vec<_>>();
        checkpoints.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(checkpoints)
    }

    fn release_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        self.coordinated(|| {
            let key = composite(&[group_id.as_slice(), checkpoint_id.as_bytes()]);
            if self
                .get::<(GroupStateCheckpointRef, StoredSnapshot)>(CHECKPOINT, &key)?
                .is_none()
            {
                return Err(StorageError::SnapshotMissing(checkpoint_id.to_owned()));
            }
            self.delete(CHECKPOINT, &key)
        })
    }
}

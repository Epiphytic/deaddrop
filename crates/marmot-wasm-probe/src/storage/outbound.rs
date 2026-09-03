use cgka_traits::{
    OutboundFanout,
    group::DisbandTombstone,
    storage::{
        DisbandCandidate, DisbandCandidateStorage, DisbandRequest, DisbandRequestStorage,
        DisbandTombstoneStorage, LeaveRequest, LeaveRequestStorage, OutboundFanoutStorage,
        OutboundIntentStorage, QueuedOutboundIntent, StorageResult,
    },
    types::{GroupId, MessageId},
};
use serde::{Deserialize, Serialize};

use super::{WasmStorage, composite};

const INTENT: &str = "intent";
const FANOUT: &str = "fanout";
const LEAVE: &str = "leave";
const DISBAND_REQUEST: &str = "disband-request";
const DISBAND_CANDIDATE: &str = "disband-candidate";
const DISBAND_TOMBSTONE: &str = "disband-tombstone";

#[derive(Clone, Serialize, Deserialize)]
struct StoredTombstone {
    group_id: GroupId,
    tombstone: DisbandTombstone,
}

impl OutboundIntentStorage for WasmStorage {
    fn put_queued_outbound_intent(&self, record: &QueuedOutboundIntent) -> StorageResult<()> {
        self.put(INTENT, record.id.as_slice(), record)
    }

    fn list_queued_outbound_intents(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<QueuedOutboundIntent>> {
        let mut intents = self
            .scan::<QueuedOutboundIntent>(INTENT)?
            .into_iter()
            .filter(|intent| &intent.group_id == group_id)
            .collect::<Vec<_>>();
        intents.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then(left.id.as_slice().cmp(right.id.as_slice()))
        });
        Ok(intents)
    }

    fn delete_queued_outbound_intent(&self, id: &MessageId) -> StorageResult<()> {
        self.delete(INTENT, id.as_slice())
    }
}

impl OutboundFanoutStorage for WasmStorage {
    fn put_outbound_fanout(&self, fanout: &OutboundFanout) -> StorageResult<()> {
        self.put(FANOUT, fanout.message_id().as_slice(), fanout)
    }

    fn outbound_fanout(&self, message_id: &MessageId) -> StorageResult<Option<OutboundFanout>> {
        self.get(FANOUT, message_id.as_slice())
    }

    fn list_outbound_fanouts(&self) -> StorageResult<Vec<OutboundFanout>> {
        let mut fanouts = self.scan::<OutboundFanout>(FANOUT)?;
        fanouts.sort_by(|left, right| {
            left.created_at_ms().cmp(&right.created_at_ms()).then(
                left.message_id()
                    .as_slice()
                    .cmp(right.message_id().as_slice()),
            )
        });
        Ok(fanouts)
    }

    fn list_outbound_fanouts_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<OutboundFanout>> {
        Ok(self
            .list_outbound_fanouts()?
            .into_iter()
            .filter(|fanout| fanout.group_id() == Some(group_id))
            .collect())
    }

    fn delete_outbound_fanout(&self, message_id: &MessageId) -> StorageResult<()> {
        self.delete(FANOUT, message_id.as_slice())
    }
}

impl LeaveRequestStorage for WasmStorage {
    fn put_leave_request(&self, request: &LeaveRequest) -> StorageResult<()> {
        self.put(LEAVE, request.group_id.as_slice(), request)
    }

    fn leave_request(&self, group_id: &GroupId) -> StorageResult<Option<LeaveRequest>> {
        self.get(LEAVE, group_id.as_slice())
    }

    fn clear_leave_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.delete(LEAVE, group_id.as_slice())
    }
}

impl DisbandRequestStorage for WasmStorage {
    fn put_disband_request(&self, request: &DisbandRequest) -> StorageResult<()> {
        self.put(DISBAND_REQUEST, request.group_id.as_slice(), request)
    }

    fn disband_request(&self, group_id: &GroupId) -> StorageResult<Option<DisbandRequest>> {
        self.get(DISBAND_REQUEST, group_id.as_slice())
    }

    fn clear_disband_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.delete(DISBAND_REQUEST, group_id.as_slice())
    }
}

impl DisbandCandidateStorage for WasmStorage {
    fn put_disband_candidate(&self, candidate: &DisbandCandidate) -> StorageResult<()> {
        self.put(
            DISBAND_CANDIDATE,
            &composite(&[
                candidate.group_id.as_slice(),
                candidate.commit_id.as_slice(),
            ]),
            candidate,
        )
    }

    fn disband_candidate(
        &self,
        group_id: &GroupId,
        commit_id: &MessageId,
    ) -> StorageResult<Option<DisbandCandidate>> {
        self.get(
            DISBAND_CANDIDATE,
            &composite(&[group_id.as_slice(), commit_id.as_slice()]),
        )
    }

    fn list_disband_candidates(&self, group_id: &GroupId) -> StorageResult<Vec<DisbandCandidate>> {
        let mut candidates = self
            .scan::<DisbandCandidate>(DISBAND_CANDIDATE)?
            .into_iter()
            .filter(|candidate| &candidate.group_id == group_id)
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.commit_id.as_slice().cmp(right.commit_id.as_slice()));
        Ok(candidates)
    }

    fn clear_disband_candidates(&self, group_id: &GroupId) -> StorageResult<()> {
        self.delete_prefix(DISBAND_CANDIDATE, &composite(&[group_id.as_slice()]))
    }
}

impl DisbandTombstoneStorage for WasmStorage {
    fn put_disband_tombstone(
        &self,
        group_id: &GroupId,
        tombstone: &DisbandTombstone,
    ) -> StorageResult<()> {
        self.coordinated(|| {
            let mut tombstone = tombstone.clone();
            if let Some(existing) = self.disband_tombstone(group_id)? {
                tombstone.announced |= existing.announced;
            }
            self.put(
                DISBAND_TOMBSTONE,
                group_id.as_slice(),
                &StoredTombstone {
                    group_id: group_id.clone(),
                    tombstone,
                },
            )
        })
    }

    fn disband_tombstone(&self, group_id: &GroupId) -> StorageResult<Option<DisbandTombstone>> {
        Ok(self
            .get::<StoredTombstone>(DISBAND_TOMBSTONE, group_id.as_slice())?
            .map(|stored| stored.tombstone))
    }

    fn list_disband_tombstones(&self) -> StorageResult<Vec<(GroupId, DisbandTombstone)>> {
        let mut tombstones = self
            .scan::<StoredTombstone>(DISBAND_TOMBSTONE)?
            .into_iter()
            .map(|stored| (stored.group_id, stored.tombstone))
            .collect::<Vec<_>>();
        tombstones.sort_by(|left, right| left.0.as_slice().cmp(right.0.as_slice()));
        Ok(tombstones)
    }

    fn mark_disband_tombstone_announced(&self, group_id: &GroupId) -> StorageResult<()> {
        self.coordinated(|| {
            if let Some(mut tombstone) = self.disband_tombstone(group_id)? {
                tombstone.announced = true;
                self.put_disband_tombstone(group_id, &tombstone)?;
            }
            Ok(())
        })
    }
}

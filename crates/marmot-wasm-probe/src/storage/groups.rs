use cgka_traits::{
    capabilities::{
        Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
    },
    group::{Group, Member},
    storage::{
        CapabilityStorage, ConvergencePolicyStorage, GroupStorage, MemberValidationCacheStorage,
        StorageError, StorageResult, TransportGroupRoute,
    },
    types::{EpochId, GroupId, MemberId},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use super::{WasmStorage, composite};

const GROUP: &str = "group";
const ROUTE: &str = "route";
const FEATURE: &str = "feature";
const MEMBER_CAPABILITY: &str = "member-capability";
const CONVERGENCE_POLICY: &str = "convergence-policy";
const VALIDATION: &str = "validation";

#[derive(Clone, Serialize, Deserialize)]
struct StoredRoute {
    transport_group_id: Vec<u8>,
    group_id: GroupId,
    source_epoch: EpochId,
}

#[derive(Serialize, Deserialize)]
struct StoredCapabilityRequirement {
    requires: Capability,
    level: RequirementLevel,
    description: String,
}

fn intern_description(description: String) -> &'static str {
    static INTERNER: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    let mut interner = INTERNER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(interned) = interner.get(description.as_str()) {
        return interned;
    }
    let interned = Box::leak(description.clone().into_boxed_str());
    interner.insert(description, interned);
    interned
}

impl GroupStorage for WasmStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()> {
        self.put(GROUP, group.id.as_slice(), group)
    }

    fn get_group(&self, id: &GroupId) -> StorageResult<Group> {
        self.get(GROUP, id.as_slice())?
            .ok_or(StorageError::NotFound)
    }

    fn delete_group(&self, id: &GroupId) -> StorageResult<()> {
        self.delete(GROUP, id.as_slice())
    }

    fn list_groups(&self) -> StorageResult<Vec<GroupId>> {
        let mut ids = self
            .scan::<Group>(GROUP)?
            .into_iter()
            .map(|group| group.id)
            .collect::<Vec<_>>();
        ids.sort_by(|left, right| left.as_slice().cmp(right.as_slice()));
        Ok(ids)
    }

    fn list_group_records(&self) -> StorageResult<Vec<Group>> {
        let mut groups = self.scan::<Group>(GROUP)?;
        groups.sort_by(|left, right| left.id.as_slice().cmp(right.id.as_slice()));
        Ok(groups)
    }

    fn put_transport_group_route(
        &self,
        transport_group_id: &[u8],
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> StorageResult<()> {
        let route = StoredRoute {
            transport_group_id: transport_group_id.to_vec(),
            group_id: group_id.clone(),
            source_epoch,
        };
        self.put(
            ROUTE,
            &composite(&[transport_group_id, &source_epoch.0.to_be_bytes()]),
            &route,
        )
    }

    fn list_transport_group_routes(&self) -> StorageResult<Vec<TransportGroupRoute>> {
        let mut routes = self
            .scan::<StoredRoute>(ROUTE)?
            .into_iter()
            .map(|route| TransportGroupRoute {
                transport_group_id: route.transport_group_id,
                group_id: route.group_id,
                source_epoch: route.source_epoch,
            })
            .collect::<Vec<_>>();
        routes.sort_by(|left, right| {
            left.transport_group_id
                .cmp(&right.transport_group_id)
                .then(left.source_epoch.cmp(&right.source_epoch))
        });
        Ok(routes)
    }

    fn delete_transport_group_route(&self, transport_group_id: &[u8]) -> StorageResult<()> {
        self.delete_prefix(ROUTE, &composite(&[transport_group_id]))
    }

    fn delete_transport_group_routes_below_epoch(
        &self,
        group_id: &GroupId,
        cutoff: EpochId,
    ) -> StorageResult<()> {
        for route in self.scan::<StoredRoute>(ROUTE)? {
            if &route.group_id == group_id && route.source_epoch < cutoff {
                self.delete(
                    ROUTE,
                    &composite(&[
                        &route.transport_group_id,
                        &route.source_epoch.0.to_be_bytes(),
                    ]),
                )?;
            }
        }
        Ok(())
    }

    fn delete_transport_group_routes_for_group(&self, group_id: &GroupId) -> StorageResult<()> {
        for route in self.scan::<StoredRoute>(ROUTE)? {
            if &route.group_id == group_id {
                self.delete(
                    ROUTE,
                    &composite(&[
                        &route.transport_group_id,
                        &route.source_epoch.0.to_be_bytes(),
                    ]),
                )?;
            }
        }
        Ok(())
    }
}

impl CapabilityStorage for WasmStorage {
    fn register_feature(
        &self,
        feature: Feature,
        requirement: CapabilityRequirement,
    ) -> StorageResult<()> {
        let key = serde_json::to_vec(&feature)
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        self.put(
            FEATURE,
            &key,
            &StoredCapabilityRequirement {
                requires: requirement.requires,
                level: requirement.level,
                description: requirement.description.to_owned(),
            },
        )
    }

    fn feature_requirement(
        &self,
        feature: &Feature,
    ) -> StorageResult<Option<CapabilityRequirement>> {
        let key = serde_json::to_vec(feature)
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        Ok(self
            .get::<StoredCapabilityRequirement>(FEATURE, &key)?
            .map(|requirement| CapabilityRequirement {
                requires: requirement.requires,
                level: requirement.level,
                description: intern_description(requirement.description),
            }))
    }

    fn save_member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
        capabilities: GroupCapabilities,
    ) -> StorageResult<()> {
        self.put(
            MEMBER_CAPABILITY,
            &composite(&[group_id.as_slice(), member.id.as_slice()]),
            &capabilities,
        )
    }

    fn member_capabilities(
        &self,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> StorageResult<Option<GroupCapabilities>> {
        self.get(
            MEMBER_CAPABILITY,
            &composite(&[group_id.as_slice(), member_id.as_slice()]),
        )
    }
}

impl ConvergencePolicyStorage for WasmStorage {
    fn put_convergence_policy(&self, group_id: &GroupId, policy: &[u8]) -> StorageResult<()> {
        self.put(CONVERGENCE_POLICY, group_id.as_slice(), &policy)
    }

    fn convergence_policy(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.get(CONVERGENCE_POLICY, group_id.as_slice())
    }
}

impl MemberValidationCacheStorage for WasmStorage {
    fn put_validated_tree_marker(&self, group_id: &GroupId, marker: &[u8]) -> StorageResult<()> {
        self.put(VALIDATION, group_id.as_slice(), &marker)
    }

    fn validated_tree_marker(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.get(VALIDATION, group_id.as_slice())
    }
}

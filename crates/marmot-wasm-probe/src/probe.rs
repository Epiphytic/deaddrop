use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cgka_engine::{
    Engine, EngineBuilder,
    account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner},
    key_package_metadata,
};
use cgka_traits::{
    AppComponentData, MarmotAppEvent, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
    default_group_components, encode_nostr_routing_v1,
    engine::{
        CgkaEngine, CreateGroupRequest, KeyPackage, KeyPackageSource, SendIntent, SendResult,
    },
    group::ProtocolProfile,
    types::{GroupId, MessageId},
};
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

use crate::{error::ProbeError, storage::WasmStorage};

const PROBE_STATE_VERSION: u16 = 1;
const MAX_PROBE_STATE_BYTES: usize = 16 * 1024 * 1024 + 1024;
const KIND_MARMOT_KEY_PACKAGE: u16 = 30_443;

/// Minimal current-profile Marmot client used by the native/browser gate.
///
/// The exported feasibility state contains the raw Nostr secret. Product code
/// must put this envelope inside the passphrase-protected vault before storing
/// it anywhere durable.
pub struct MarmotProbe {
    keys: Keys,
    storage: WasmStorage,
    engine: Engine<WasmStorage>,
}

#[derive(Serialize, Deserialize)]
struct ProbeState {
    version: u16,
    secret_key_hex: String,
    storage: Vec<u8>,
}

#[derive(Deserialize)]
struct KeyPackageResponse {
    relay_url: String,
    event: Event,
}

#[derive(Clone)]
struct NostrAccountIdentityProofSigner {
    keys: Keys,
}

impl AccountIdentityProofSigner for NostrAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("account identity mismatch".into());
        }
        let event = request
            .proof_event()?
            .sign_with_keys(&self.keys)
            .map_err(|_| "account proof signing failed".to_owned())?;
        request.signature_from_signed_event(event)
    }
}

impl MarmotProbe {
    pub fn create(secret_key_hex: &str) -> Result<Self, ProbeError> {
        let keys = Keys::parse(secret_key_hex)
            .map_err(|_| ProbeError::InvalidInput("invalid Nostr secret key".into()))?;
        Self::build(keys, WasmStorage::new(), false)
    }

    pub fn from_state(state: &[u8]) -> Result<Self, ProbeError> {
        if state.len() > MAX_PROBE_STATE_BYTES {
            return Err(ProbeError::SnapshotTooLarge);
        }
        let (state, remainder): (ProbeState, &[u8]) =
            postcard::take_from_bytes(state).map_err(|_| ProbeError::Serialization)?;
        if !remainder.is_empty() || state.version != PROBE_STATE_VERSION {
            return Err(ProbeError::Serialization);
        }
        let keys = Keys::parse(&state.secret_key_hex).map_err(|_| ProbeError::Serialization)?;
        let storage = WasmStorage::import(&state.storage)?;
        Self::build(keys, storage, true)
    }

    fn build(keys: Keys, storage: WasmStorage, hydrate: bool) -> Result<Self, ProbeError> {
        let mut supported = default_group_components();
        supported.insert(NOSTR_ROUTING_COMPONENT_ID);
        let proof_signer = Arc::new(NostrAccountIdentityProofSigner { keys: keys.clone() });
        let peeler = NostrMlsPeeler::new().with_welcome_signer(keys.clone());
        let mut engine = EngineBuilder::new(storage.clone())
            .identity(keys.public_key().to_bytes().to_vec())
            .account_identity_proof_signer(proof_signer)
            .supported_app_components(supported)
            .protocol_profile(ProtocolProfile::Current)
            .peeler(Box::new(peeler))
            .build()
            .map_err(|_| ProbeError::Marmot)?;
        if hydrate {
            engine
                .hydrate_all_stored_groups()
                .map_err(|_| ProbeError::Marmot)?;
        }
        Ok(Self {
            keys,
            storage,
            engine,
        })
    }

    pub async fn create_key_package(
        &mut self,
        relay_url: &str,
        now_seconds: u64,
    ) -> Result<String, ProbeError> {
        let relay = NostrRoutingV1::new([0_u8; 32], vec![relay_url.to_owned()])
            .map_err(ProbeError::InvalidInput)?
            .relays
            .into_iter()
            .next()
            .ok_or_else(|| ProbeError::InvalidInput("relay URL is required".into()))?;
        let key_package = self
            .engine
            .fresh_key_package()
            .await
            .map_err(|_| ProbeError::Marmot)?;
        let metadata = key_package_metadata(&key_package).map_err(|_| ProbeError::Marmot)?;
        let tags = vec![
            vec!["d".into(), "deaddrop".into()],
            vec!["mls_protocol_version".into(), "1.0".into()],
            vec!["i".into(), metadata.key_package_ref_hex],
            vec![
                "mls_ciphersuite".into(),
                format!("0x{:04x}", metadata.ciphersuite),
            ],
            values_tag("mls_extensions", &metadata.mls_extensions),
            values_tag("mls_proposals", &metadata.mls_proposals),
            values_tag(
                "app_components",
                &metadata
                    .app_components
                    .into_iter()
                    .filter(|id| *id >= 0x8000)
                    .collect::<Vec<_>>(),
            ),
        ];
        let tags = tags
            .into_iter()
            .map(Tag::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProbeError::Marmot)?;
        let event = EventBuilder::new(
            Kind::Custom(KIND_MARMOT_KEY_PACKAGE),
            BASE64_STANDARD.encode(key_package.bytes()),
        )
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(now_seconds))
        .sign_with_keys(&self.keys)
        .map_err(|_| ProbeError::Marmot)?;
        encode_json(&json!({
            "type": "key_package",
            "relay_url": relay,
            "event": event,
        }))
    }

    pub async fn create_conversation(
        &mut self,
        key_package_event_json: &str,
        group_h_hex: &str,
    ) -> Result<String, ProbeError> {
        let response: KeyPackageResponse = serde_json::from_str(key_package_event_json)
            .map_err(|_| ProbeError::InvalidInput("invalid KeyPackage response JSON".into()))?;
        response
            .event
            .verify()
            .map_err(|_| ProbeError::InvalidInput("invalid KeyPackage event signature".into()))?;
        if response.event.kind != Kind::Custom(KIND_MARMOT_KEY_PACKAGE) {
            return Err(ProbeError::InvalidInput("expected kind 30443".into()));
        }
        let key_package_bytes = BASE64_STANDARD
            .decode(response.event.content.as_bytes())
            .map_err(|_| ProbeError::InvalidInput("invalid KeyPackage content".into()))?;
        let key_package = KeyPackage {
            bytes: key_package_bytes,
            source: Some(KeyPackageSource {
                event_id: MessageId::new(response.event.id.to_bytes().to_vec()),
            }),
            protocol_profile: ProtocolProfile::Current,
        };
        let metadata = key_package_metadata(&key_package)
            .map_err(|_| ProbeError::InvalidInput("invalid current-profile KeyPackage".into()))?;
        if metadata.credential_identity_hex != response.event.pubkey.to_hex() {
            return Err(ProbeError::InvalidInput(
                "KeyPackage author does not match its MLS identity".into(),
            ));
        }
        let group_h = decode_exact_32("h", group_h_hex)?;
        let routing = NostrRoutingV1::new(group_h, vec![response.relay_url.clone()])
            .map_err(ProbeError::InvalidInput)?;
        let app_components = vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: encode_nostr_routing_v1(&routing).map_err(ProbeError::InvalidInput)?,
        }];
        let (group_id, result) = self
            .engine
            .create_group(CreateGroupRequest {
                name: "deaddrop".into(),
                description: "one-to-one deaddrop".into(),
                members: vec![key_package],
                required_features: Vec::new(),
                app_components,
                initial_admins: Vec::new(),
            })
            .await
            .map_err(|_| ProbeError::Marmot)?;
        let SendResult::FoundingGroupCreated { mut welcomes } = result else {
            return Err(ProbeError::Marmot);
        };
        if welcomes.len() != 1 {
            return Err(ProbeError::Marmot);
        }
        let welcome = NostrTransportEvent::from_transport_message(&welcomes.remove(0))
            .map_err(|_| ProbeError::Marmot)?;
        encode_json(&json!({
            "type": "conversation_created",
            "group_id": hex::encode(group_id.as_slice()),
            "welcome": welcome,
        }))
    }

    pub async fn join_welcome(&mut self, gift_wrap_json: &str) -> Result<String, ProbeError> {
        let event = Event::from_json(gift_wrap_json)
            .map_err(|_| ProbeError::InvalidInput("invalid Welcome event JSON".into()))?;
        let transport = NostrTransportEvent::from_nostr_event(&event)
            .and_then(|event| event.to_transport_message())
            .map_err(|_| ProbeError::InvalidInput("invalid Welcome event".into()))?;
        let group_id = self
            .engine
            .join_welcome(transport)
            .await
            .map_err(|_| ProbeError::Marmot)?;
        encode_json(&json!({
            "type": "conversation_joined",
            "group_id": hex::encode(group_id.as_slice()),
        }))
    }

    pub async fn send_chat(
        &mut self,
        group_id_hex: &str,
        content: &str,
        created_at: u64,
    ) -> Result<String, ProbeError> {
        let group_id = GroupId::new(
            hex::decode(group_id_hex)
                .map_err(|_| ProbeError::InvalidInput("invalid group id hex".into()))?,
        );
        let app_event = MarmotAppEvent::new(
            self.keys.public_key().to_hex(),
            created_at,
            9,
            Vec::new(),
            content,
        );
        let result = self
            .engine
            .send(SendIntent::AppMessage {
                group_id,
                payload: app_event.encode().map_err(|_| ProbeError::Marmot)?,
            })
            .await
            .map_err(|_| ProbeError::Marmot)?;
        let SendResult::ApplicationMessage { msg, .. } = result else {
            return Err(ProbeError::Marmot);
        };
        let event =
            NostrTransportEvent::from_transport_message(&msg).map_err(|_| ProbeError::Marmot)?;
        encode_json(&json!({ "type": "chat_sent", "event": event }))
    }

    pub async fn ingest(&mut self, event_json: &str) -> Result<String, ProbeError> {
        let event = Event::from_json(event_json)
            .map_err(|_| ProbeError::InvalidInput("invalid Nostr event JSON".into()))?;
        let transport = NostrTransportEvent::from_nostr_event(&event)
            .and_then(|event| event.to_transport_message())
            .map_err(|_| ProbeError::InvalidInput("invalid Marmot transport event".into()))?;
        self.engine
            .ingest(transport)
            .await
            .map_err(|_| ProbeError::Marmot)?;
        let messages = self
            .engine
            .drain_events()
            .into_iter()
            .filter_map(|event| match event {
                cgka_traits::engine::GroupEvent::MessageReceived { payload, .. } => {
                    MarmotAppEvent::decode(&payload).ok()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        encode_json(&json!({ "type": "ingest", "messages": messages }))
    }

    pub fn export_state(&self) -> Result<Vec<u8>, ProbeError> {
        let encoded = postcard::to_allocvec(&ProbeState {
            version: PROBE_STATE_VERSION,
            secret_key_hex: self.keys.secret_key().to_secret_hex(),
            storage: self.storage.export()?,
        })
        .map_err(|_| ProbeError::Serialization)?;
        if encoded.len() > MAX_PROBE_STATE_BYTES {
            return Err(ProbeError::SnapshotTooLarge);
        }
        Ok(encoded)
    }
}

fn values_tag(name: &str, values: &[u16]) -> Vec<String> {
    std::iter::once(name.to_owned())
        .chain(values.iter().map(|id| format!("0x{id:04x}")))
        .collect()
}

fn decode_exact_32(label: &str, value: &str) -> Result<[u8; 32], ProbeError> {
    let bytes =
        hex::decode(value).map_err(|_| ProbeError::InvalidInput(format!("invalid {label} hex")))?;
    bytes
        .try_into()
        .map_err(|_| ProbeError::InvalidInput(format!("{label} must be exactly 32 bytes")))
}

fn encode_json(value: &Value) -> Result<String, ProbeError> {
    serde_json::to_string(value).map_err(|_| ProbeError::Serialization)
}

use cgka_traits::{
    capabilities::GroupCapabilities,
    group::{Group, ProtocolProfile},
    message::{MessageRecord, MessageState},
    storage::{
        ConvergencePolicyStorage, GroupStateCheckpointRef, GroupStorage, KeyPackageBundleStorage,
        MessageStorage, StorageError, StorageProvider, WelcomeStorage,
    },
    types::{EpochId, GroupId, MessageId},
    welcome::PendingWelcome,
};
use marmot_wasm_probe::storage::WasmStorage;
use openmls::group::GroupId as OpenMlsGroupId;
use openmls_traits::storage::{
    CURRENT_VERSION, Entity, Key, StorageProvider as OpenMlsStorageProvider,
    traits::{
        EpochKey as OpenMlsEpochKey, GroupState as OpenMlsGroupState,
        HpkeKeyPair as OpenMlsHpkeKeyPair, ProposalRef as OpenMlsProposalRef,
        QueuedProposal as OpenMlsQueuedProposal,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, mpsc},
    thread,
};

#[test]
fn implements_the_complete_mdk_storage_provider_contract() {
    fn assert_storage_provider<T: StorageProvider>() {}

    assert_storage_provider::<WasmStorage>();
}

#[test]
fn transaction_rolls_back_every_namespace() {
    let store = WasmStorage::new();
    let result: Result<(), cgka_traits::storage::StorageError> = store.with_transaction(|tx| {
        tx.test_put_raw("groups", b"g", b"one")?;
        tx.test_put_raw("messages", b"m", b"two")?;
        Err(cgka_traits::storage::StorageError::Backend(
            "rollback".into(),
        ))
    });

    assert!(result.is_err());
    assert_eq!(store.test_get_raw("groups", b"g").unwrap(), None);
    assert_eq!(store.test_get_raw("messages", b"m").unwrap(), None);
}

#[test]
fn transaction_rolls_back_openmls_and_rejects_nesting() {
    let store = WasmStorage::new();
    store
        .mls_storage()
        .values
        .write()
        .unwrap()
        .insert(b"before".to_vec(), b"kept".to_vec());

    let result: Result<(), StorageError> = store.with_transaction(|transaction| {
        transaction
            .mls_storage()
            .values
            .write()
            .unwrap()
            .insert(b"during".to_vec(), b"rolled-back".to_vec());
        let nested: Result<(), StorageError> = transaction.with_transaction(|_| Ok(()));
        assert!(matches!(nested, Err(StorageError::Backend(_))));
        Err(StorageError::Backend("rollback".into()))
    });

    assert!(result.is_err());
    let values = store.mls_storage().values.read().unwrap();
    assert_eq!(values.get(b"before".as_slice()), Some(&b"kept".to_vec()));
    assert_eq!(values.get(b"during".as_slice()), None);
}

#[test]
fn concurrent_write_waits_for_rollback_and_is_not_erased() {
    let store = Arc::new(WasmStorage::new());
    let (transaction_ready_tx, transaction_ready_rx) = mpsc::channel();
    let (release_transaction_tx, release_transaction_rx) = mpsc::channel();
    let transaction_store = Arc::clone(&store);
    let transaction = thread::spawn(move || {
        let result: Result<(), StorageError> = transaction_store.with_transaction(|storage| {
            storage.test_put_raw("probe", b"inside", b"rollback")?;
            transaction_ready_tx.send(()).unwrap();
            release_transaction_rx.recv().unwrap();
            Err(StorageError::Backend("rollback".into()))
        });
        assert!(result.is_err());
    });
    transaction_ready_rx.recv().unwrap();

    let (write_started_tx, write_started_rx) = mpsc::channel();
    let (write_finished_tx, write_finished_rx) = mpsc::channel();
    let writer_store = Arc::clone(&store);
    let writer = thread::spawn(move || {
        write_started_tx.send(()).unwrap();
        writer_store
            .test_put_raw("probe", b"outside", b"preserve")
            .unwrap();
        write_finished_tx.send(()).unwrap();
    });
    write_started_rx.recv().unwrap();
    assert!(matches!(
        write_finished_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    release_transaction_tx.send(()).unwrap();
    transaction.join().unwrap();
    writer.join().unwrap();

    assert_eq!(store.test_get_raw("probe", b"inside").unwrap(), None);
    assert_eq!(
        store.test_get_raw("probe", b"outside").unwrap(),
        Some(b"preserve".to_vec())
    );
}

#[test]
fn panic_does_not_leave_transaction_marked_active() {
    let store = WasmStorage::new();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), StorageError> = store.with_transaction(|_| panic!("test panic"));
    }));
    assert!(panic.is_err());

    let next: Result<(), StorageError> = store.with_transaction(|_| Ok(()));
    assert!(next.is_ok());
}

#[test]
fn exported_state_round_trips_byte_for_byte() {
    let store = WasmStorage::new();
    store.test_put_raw("probe", b"key", b"value").unwrap();

    let encoded = store.export().unwrap();
    let restored = WasmStorage::import(&encoded).unwrap();

    assert_eq!(
        restored.test_get_raw("probe", b"key").unwrap(),
        Some(b"value".to_vec())
    );
    assert_eq!(restored.export().unwrap(), encoded);
}

#[test]
fn exported_state_includes_openmls_entries() {
    let store = WasmStorage::new();
    store
        .mls_storage()
        .values
        .write()
        .unwrap()
        .insert(b"openmls-key".to_vec(), b"secret-value".to_vec());

    let restored = WasmStorage::import(&store.export().unwrap()).unwrap();

    assert_eq!(
        restored
            .mls_storage()
            .values
            .read()
            .unwrap()
            .get(b"openmls-key".as_slice()),
        Some(&b"secret-value".to_vec())
    );
}

#[test]
fn group_snapshot_rolls_back_typed_and_openmls_state() {
    let store = WasmStorage::new();
    let group_id = GroupId::new(b"group-one".to_vec());
    let original = sample_group(group_id.clone(), 3);
    store.put_group(&original).unwrap();
    write_openmls_group_state(&store, &group_id, b"epoch-three");
    store
        .create_group_snapshot(&group_id, "before-change")
        .unwrap();

    store.put_group(&sample_group(group_id.clone(), 4)).unwrap();
    write_openmls_group_state(&store, &group_id, b"epoch-four");
    store
        .rollback_group_to_snapshot(&group_id, "before-change")
        .unwrap();

    assert_eq!(store.get_group(&group_id).unwrap(), original);
    assert_eq!(read_openmls_group_state(&store, &group_id), b"epoch-three");
}

#[test]
fn group_rollback_preserves_unrelated_group_and_account_state() {
    let store = WasmStorage::new();
    let first_id = GroupId::new(b"group-one".to_vec());
    let second_id = GroupId::new(b"group-two".to_vec());
    store.put_group(&sample_group(first_id.clone(), 1)).unwrap();
    store
        .put_group(&sample_group(second_id.clone(), 1))
        .unwrap();
    write_openmls_group_state(&store, &first_id, b"first-before");
    store
        .test_put_raw("account", b"setting", b"before")
        .unwrap();
    store.create_group_snapshot(&first_id, "first-v1").unwrap();

    store.put_group(&sample_group(first_id.clone(), 2)).unwrap();
    let second_after_snapshot = sample_group(second_id.clone(), 9);
    store.put_group(&second_after_snapshot).unwrap();
    write_openmls_group_state(&store, &first_id, b"first-after");
    write_openmls_group_state(&store, &second_id, b"second-after");
    store.test_put_raw("account", b"setting", b"after").unwrap();
    store
        .rollback_group_to_snapshot(&first_id, "first-v1")
        .unwrap();

    assert_eq!(store.get_group(&first_id).unwrap().epoch, EpochId(1));
    assert_eq!(store.get_group(&second_id).unwrap(), second_after_snapshot);
    assert_eq!(read_openmls_group_state(&store, &first_id), b"first-before");
    assert_eq!(
        read_openmls_group_state(&store, &second_id),
        b"second-after"
    );
    assert_eq!(
        store.test_get_raw("account", b"setting").unwrap().unwrap(),
        b"after"
    );
    assert_eq!(
        store.list_group_snapshots(&first_id).unwrap(),
        vec!["first-v1"]
    );
}

#[test]
fn group_snapshot_does_not_capture_a_group_with_a_prefixed_identifier() {
    let store = WasmStorage::new();
    let short_id = GroupId::new(b"a".to_vec());
    let long_id = GroupId::new(b"ab".to_vec());
    store.put_group(&sample_group(short_id.clone(), 1)).unwrap();
    store.put_group(&sample_group(long_id.clone(), 1)).unwrap();
    write_openmls_group_state(&store, &short_id, b"short-before");
    write_openmls_group_state(&store, &long_id, b"long-before");
    store
        .create_group_snapshot(&short_id, "short-snapshot")
        .unwrap();

    write_openmls_group_state(&store, &short_id, b"short-after");
    write_openmls_group_state(&store, &long_id, b"long-after");
    store
        .rollback_group_to_snapshot(&short_id, "short-snapshot")
        .unwrap();

    assert_eq!(read_openmls_group_state(&store, &short_id), b"short-before");
    assert_eq!(read_openmls_group_state(&store, &long_id), b"long-after");
}

#[test]
fn group_snapshot_captures_composite_openmls_group_keys() {
    let store = WasmStorage::new();
    let group_id = GroupId::new(b"composite-keys".to_vec());
    store.put_group(&sample_group(group_id.clone(), 1)).unwrap();
    let openmls_group_id = openmls_group_id(&group_id);
    let proposal_ref = TestProposalRef(b"proposal".to_vec());
    let epoch_key = TestEpochKey(b"epoch".to_vec());
    OpenMlsStorageProvider::queue_proposal(
        store.mls_storage(),
        &openmls_group_id,
        &proposal_ref,
        &TestQueuedProposal(b"proposal-before".to_vec()),
    )
    .unwrap();
    OpenMlsStorageProvider::write_encryption_epoch_key_pairs(
        store.mls_storage(),
        &openmls_group_id,
        &epoch_key,
        7,
        &[TestHpkeKeyPair(b"key-before".to_vec())],
    )
    .unwrap();
    store
        .create_group_snapshot(&group_id, "composite-snapshot")
        .unwrap();

    OpenMlsStorageProvider::queue_proposal(
        store.mls_storage(),
        &openmls_group_id,
        &proposal_ref,
        &TestQueuedProposal(b"proposal-after".to_vec()),
    )
    .unwrap();
    OpenMlsStorageProvider::write_encryption_epoch_key_pairs(
        store.mls_storage(),
        &openmls_group_id,
        &epoch_key,
        7,
        &[TestHpkeKeyPair(b"key-after".to_vec())],
    )
    .unwrap();
    store
        .rollback_group_to_snapshot(&group_id, "composite-snapshot")
        .unwrap();

    let proposals: Vec<(TestProposalRef, TestQueuedProposal)> =
        OpenMlsStorageProvider::queued_proposals(store.mls_storage(), &openmls_group_id).unwrap();
    assert_eq!(
        proposals,
        vec![(
            proposal_ref,
            TestQueuedProposal(b"proposal-before".to_vec())
        )]
    );
    let key_pairs: Vec<TestHpkeKeyPair> = OpenMlsStorageProvider::encryption_epoch_key_pairs(
        store.mls_storage(),
        &openmls_group_id,
        &epoch_key,
        7,
    )
    .unwrap();
    assert_eq!(key_pairs, vec![TestHpkeKeyPair(b"key-before".to_vec())]);
}

#[test]
fn replacing_a_named_snapshot_does_not_embed_the_previous_snapshot() {
    let store = WasmStorage::new();
    let group_id = GroupId::new(b"stable-snapshot".to_vec());
    store.put_group(&sample_group(group_id.clone(), 1)).unwrap();

    store.create_group_snapshot(&group_id, "same-name").unwrap();
    let first = store.export().unwrap();
    store.create_group_snapshot(&group_id, "same-name").unwrap();
    let second = store.export().unwrap();

    assert_eq!(second, first);
}

#[test]
fn group_lists_are_sorted_by_opaque_identifier() {
    let store = WasmStorage::new();
    for id in [b"z".as_slice(), b"a".as_slice(), b"m".as_slice()] {
        store
            .put_group(&sample_group(GroupId::new(id.to_vec()), 1))
            .unwrap();
    }

    assert_eq!(
        store.list_groups().unwrap(),
        vec![
            GroupId::new(b"a".to_vec()),
            GroupId::new(b"m".to_vec()),
            GroupId::new(b"z".to_vec())
        ]
    );
}

#[test]
fn checkpoint_id_cannot_be_reused_for_different_state() {
    let store = WasmStorage::new();
    let group_id = GroupId::new(b"checkpoint-group".to_vec());
    store.put_group(&sample_group(group_id.clone(), 1)).unwrap();
    let checkpoint = GroupStateCheckpointRef {
        id: "commit-a".into(),
        resulting_epoch: EpochId(1),
    };
    store
        .create_group_state_checkpoint(&group_id, &checkpoint)
        .unwrap();

    store.put_group(&sample_group(group_id.clone(), 2)).unwrap();

    assert!(matches!(
        store.create_group_state_checkpoint(&group_id, &checkpoint),
        Err(StorageError::AlreadyExists)
    ));
}

#[test]
fn canonical_checkpoint_does_not_rewind_message_work() {
    let store = WasmStorage::new();
    let group_id = GroupId::new(b"checkpoint-scope".to_vec());
    let message_id = MessageId::new(b"message-after-commit".to_vec());
    store.put_group(&sample_group(group_id.clone(), 1)).unwrap();
    store
        .put_convergence_policy(&group_id, b"policy-before")
        .unwrap();
    store
        .put_message(&MessageRecord {
            id: message_id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(1),
            state: MessageState::Created,
            payload: b"before".to_vec(),
            deferred_peel: None,
        })
        .unwrap();
    let checkpoint = GroupStateCheckpointRef {
        id: "commit-scope".into(),
        resulting_epoch: EpochId(1),
    };
    store
        .create_group_state_checkpoint(&group_id, &checkpoint)
        .unwrap();

    store.put_group(&sample_group(group_id.clone(), 2)).unwrap();
    store
        .put_convergence_policy(&group_id, b"policy-after")
        .unwrap();
    store
        .put_message(&MessageRecord {
            id: message_id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(2),
            state: MessageState::Processed,
            payload: b"after".to_vec(),
            deferred_peel: None,
        })
        .unwrap();
    store
        .restore_group_state_checkpoint(&group_id, &checkpoint.id)
        .unwrap();

    assert_eq!(store.get_group(&group_id).unwrap().epoch, EpochId(1));
    let message = store.get_message(&message_id).unwrap();
    assert_eq!(message.epoch, EpochId(2));
    assert_eq!(message.state, MessageState::Processed);
    assert_eq!(message.payload, b"after");
    assert_eq!(
        store.convergence_policy(&group_id).unwrap().unwrap(),
        b"policy-after"
    );
}

#[test]
fn snapshot_creation_requires_an_existing_group() {
    let store = WasmStorage::new();
    let group_id = GroupId::new(b"not-created".to_vec());
    let checkpoint = GroupStateCheckpointRef {
        id: "missing-group-checkpoint".into(),
        resulting_epoch: EpochId(1),
    };

    assert!(matches!(
        store.create_group_snapshot(&group_id, "missing-group-snapshot"),
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        store.create_group_state_checkpoint(&group_id, &checkpoint),
        Err(StorageError::NotFound)
    ));
}

#[test]
fn releasing_missing_snapshots_reports_snapshot_missing() {
    let store = WasmStorage::new();
    let group_id = GroupId::new(b"missing-release".to_vec());
    store.put_group(&sample_group(group_id.clone(), 1)).unwrap();

    assert!(matches!(
        store.release_group_snapshot(&group_id, "missing-snapshot"),
        Err(StorageError::SnapshotMissing(name)) if name == "missing-snapshot"
    ));
    assert!(matches!(
        store.release_group_state_checkpoint(&group_id, "missing-checkpoint"),
        Err(StorageError::SnapshotMissing(name)) if name == "missing-checkpoint"
    ));
}

#[test]
fn taking_a_welcome_consumes_it_once() {
    let store = WasmStorage::new();
    let welcome = PendingWelcome {
        message_id: MessageId::new(b"welcome-one".to_vec()),
        group_id: GroupId::new(b"group-one".to_vec()),
        welcome_bytes: b"opaque-welcome".to_vec(),
    };
    store.put_welcome(&welcome).unwrap();

    assert_eq!(store.take_welcome(&welcome.message_id).unwrap(), welcome);
    assert!(matches!(
        store.take_welcome(&MessageId::new(b"welcome-one".to_vec())),
        Err(StorageError::NotFound)
    ));
}

#[test]
fn malformed_welcome_is_not_consumed() {
    let store = WasmStorage::new();
    let id = MessageId::new(b"malformed".to_vec());
    store
        .test_put_raw("welcome", id.as_slice(), b"not-json")
        .unwrap();

    assert!(matches!(
        store.take_welcome(&id),
        Err(StorageError::Serialization(_))
    ));
    assert_eq!(
        store.test_get_raw("welcome", id.as_slice()).unwrap(),
        Some(b"not-json".to_vec())
    );
}

#[test]
fn key_package_bundles_can_be_enumerated_and_deleted() {
    let store = WasmStorage::new();
    let storage_key = b"key-package-ref";
    let mut openmls_key = b"KeyPackage".to_vec();
    openmls_key.extend_from_slice(storage_key);
    openmls_key.extend_from_slice(&1_u16.to_be_bytes());
    store
        .mls_storage()
        .values
        .write()
        .unwrap()
        .insert(openmls_key.clone(), b"private-bundle".to_vec());

    let bundles = store.stored_key_package_bundles().unwrap();
    assert_eq!(bundles.len(), 1);
    assert_eq!(bundles[0].storage_key, storage_key);
    assert_eq!(bundles[0].value.as_slice(), b"private-bundle");

    store.delete_stored_key_package_bundle(storage_key).unwrap();
    assert!(
        !store
            .mls_storage()
            .values
            .read()
            .unwrap()
            .contains_key(&openmls_key)
    );
}

#[test]
fn import_rejects_trailing_bytes_and_unknown_versions() {
    let encoded = WasmStorage::new().export().unwrap();

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(WasmStorage::import(&trailing).is_err());

    let mut unknown_version = encoded;
    unknown_version[0] = 2;
    assert!(WasmStorage::import(&unknown_version).is_err());
}

#[test]
fn export_rejects_snapshots_larger_than_the_import_limit() {
    let store = WasmStorage::new();
    store
        .test_put_raw("oversized", b"value", &vec![0_u8; 16 * 1024 * 1024])
        .unwrap();

    assert!(matches!(
        store.export(),
        Err(marmot_wasm_probe::error::ProbeError::SnapshotTooLarge)
    ));
}

fn sample_group(id: GroupId, epoch: u64) -> Group {
    Group {
        id,
        name: "sample".into(),
        description: "storage contract".into(),
        epoch: EpochId(epoch),
        members: Vec::new(),
        required_capabilities: GroupCapabilities::default(),
        protocol_profile: ProtocolProfile::Current,
        removed: false,
        unrecoverable: false,
        disbanded: None,
        join_epoch: EpochId(0),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestOpenMlsGroupState(Vec<u8>);

impl Entity<CURRENT_VERSION> for TestOpenMlsGroupState {}
impl OpenMlsGroupState<CURRENT_VERSION> for TestOpenMlsGroupState {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestProposalRef(Vec<u8>);

impl Key<CURRENT_VERSION> for TestProposalRef {}
impl Entity<CURRENT_VERSION> for TestProposalRef {}
impl OpenMlsProposalRef<CURRENT_VERSION> for TestProposalRef {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestQueuedProposal(Vec<u8>);

impl Entity<CURRENT_VERSION> for TestQueuedProposal {}
impl OpenMlsQueuedProposal<CURRENT_VERSION> for TestQueuedProposal {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestEpochKey(Vec<u8>);

impl Key<CURRENT_VERSION> for TestEpochKey {}
impl OpenMlsEpochKey<CURRENT_VERSION> for TestEpochKey {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestHpkeKeyPair(Vec<u8>);

impl Entity<CURRENT_VERSION> for TestHpkeKeyPair {}
impl OpenMlsHpkeKeyPair<CURRENT_VERSION> for TestHpkeKeyPair {}

fn openmls_group_id(group_id: &GroupId) -> OpenMlsGroupId {
    OpenMlsGroupId::from_slice(group_id.as_slice())
}

fn write_openmls_group_state(store: &WasmStorage, group_id: &GroupId, value: &[u8]) {
    OpenMlsStorageProvider::write_group_state(
        store.mls_storage(),
        &openmls_group_id(group_id),
        &TestOpenMlsGroupState(value.to_vec()),
    )
    .unwrap();
}

fn read_openmls_group_state(store: &WasmStorage, group_id: &GroupId) -> Vec<u8> {
    OpenMlsStorageProvider::group_state::<TestOpenMlsGroupState, _>(
        store.mls_storage(),
        &openmls_group_id(group_id),
    )
    .unwrap()
    .unwrap()
    .0
}

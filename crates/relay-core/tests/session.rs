use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    thread,
};

use deaddrop_protocol_core::{AuthorizedQuery, ValidatedEvent};
use deaddrop_relay_core::{
    ChallengeSource, Clock, RelayHub, Session, SessionLimits, SessionOutput, Store, StoreFuture,
    StoreOutcome, StrictClientMessage,
};
use futures::{channel::oneshot, executor::block_on, task::noop_waker_ref};
use nostr::{
    Event, EventBuilder, Filter, Keys, Kind, RelayMessage, RelayUrl, SubscriptionId, Timestamp,
};

const NOW: u64 = 1_700_000_000;

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now_seconds(&self) -> u64 {
        NOW
    }
}

struct CounterSource(u8);

impl ChallengeSource for CounterSource {
    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

#[derive(Default)]
struct StoreState {
    seeded: Vec<Event>,
    stored: Vec<Event>,
    query_calls: usize,
    put_calls: usize,
    query_gate: Option<Arc<OperationGate>>,
    put_gate: Option<Arc<OperationGate>>,
    fail_next_query: bool,
}

#[derive(Debug, Clone, Copy)]
struct FakeError;

struct OperationGate {
    started: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

#[derive(Clone, Default)]
struct FakeStore(Arc<Mutex<StoreState>>);

impl Store for FakeStore {
    type Error = FakeError;

    fn query<'a>(
        &'a self,
        _queries: &'a [AuthorizedQuery],
        _now_seconds: u64,
        _max_results: usize,
    ) -> StoreFuture<'a, Result<Vec<Event>, Self::Error>> {
        Box::pin(async move {
            let (seeded, gate, fail) = {
                let mut state = self.0.lock().unwrap();
                state.query_calls += 1;
                let fail = core::mem::take(&mut state.fail_next_query);
                (state.seeded.clone(), state.query_gate.take(), fail)
            };
            await_gate(gate).await;
            if fail { Err(FakeError) } else { Ok(seeded) }
        })
    }

    fn put(&self, event: ValidatedEvent) -> StoreFuture<'_, Result<StoreOutcome, Self::Error>> {
        Box::pin(async move {
            let (outcome, gate) = {
                let mut state = self.0.lock().unwrap();
                state.put_calls += 1;
                let outcome = if state
                    .stored
                    .iter()
                    .any(|stored| stored.id == event.event().id)
                {
                    StoreOutcome::Duplicate
                } else {
                    state.stored.push(event.event().clone());
                    StoreOutcome::Stored
                };
                (outcome, state.put_gate.take())
            };
            await_gate(gate).await;
            Ok(outcome)
        })
    }
}

async fn await_gate(gate: Option<Arc<OperationGate>>) {
    if let Some(gate) = gate {
        if let Some(started) = gate.started.lock().unwrap().take() {
            let _ = started.send(());
        }
        let release = gate.release.lock().unwrap().take();
        if let Some(release) = release {
            let _ = release.await;
        }
    }
}

impl FakeStore {
    fn gate_next_query(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        install_gate(&mut self.0.lock().unwrap().query_gate)
    }

    fn gate_next_put(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        install_gate(&mut self.0.lock().unwrap().put_gate)
    }

    fn fail_next_query(&self) {
        self.0.lock().unwrap().fail_next_query = true;
    }
}

fn install_gate(
    slot: &mut Option<Arc<OperationGate>>,
) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    *slot = Some(Arc::new(OperationGate {
        started: Mutex::new(Some(started_tx)),
        release: Mutex::new(Some(release_rx)),
    }));
    (started_rx, release_tx)
}

fn keys(byte: u8) -> Keys {
    Keys::parse(&format!("{byte:02x}").repeat(32)).unwrap()
}

fn relay_url() -> RelayUrl {
    RelayUrl::parse("ws://127.0.0.1:8765").unwrap()
}

fn metadata(keys: &Keys, content: &str) -> Event {
    EventBuilder::new(Kind::Metadata, content)
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(keys)
        .unwrap()
}

fn auth(keys: &Keys, challenge: &str) -> Event {
    EventBuilder::auth(challenge, relay_url())
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(keys)
        .unwrap()
}

fn limits() -> SessionLimits {
    SessionLimits {
        max_subscriptions: 1,
        max_history_events: 16,
        max_pending_outputs: 16,
        max_in_flight_tasks: 4,
    }
}

fn new_session(
    store: FakeStore,
    limits: SessionLimits,
) -> (
    RelayHub<FakeStore>,
    Session<FakeStore, FixedClock, CounterSource>,
) {
    let hub = RelayHub::new(store);
    let session = Session::new(
        hub.clone(),
        relay_url(),
        FixedClock,
        CounterSource(1),
        limits,
    );
    (hub, session)
}

fn drain(session: &mut Session<FakeStore, FixedClock, CounterSource>) -> Vec<SessionOutput> {
    std::iter::from_fn(|| session.next_output()).collect()
}

fn expect_initial_challenge(session: &mut Session<FakeStore, FixedClock, CounterSource>) -> String {
    let output = session.next_output().expect("relay must challenge first");
    let debug = format!("{output:?}");
    let SessionOutput::Send(RelayMessage::Auth { challenge }) = output else {
        panic!("first output was not AUTH")
    };
    let challenge = challenge.into_owned();
    assert!(!debug.contains(&challenge));
    assert_eq!(challenge.len(), 64);
    assert!(
        challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    challenge
}

fn authenticate(session: &mut Session<FakeStore, FixedClock, CounterSource>, account: &Keys) {
    let challenge = session.challenge().to_owned();
    block_on(session.handle(StrictClientMessage::Auth(auth(account, &challenge))));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: true, .. }))
    ));
}

#[test]
fn challenge_is_first_and_unauthenticated_reads_and_writes_are_rejected() {
    let store = FakeStore::default();
    let (_hub, mut session) = new_session(store.clone(), limits());
    expect_initial_challenge(&mut session);

    let id = SubscriptionId::new("unauth");
    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: id.clone(),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Closed { subscription_id, message }))
            if subscription_id.as_ref() == &id && message.starts_with("auth-required:")
    ));

    let event = metadata(&keys(0x11), "{}");
    let event_id = event.id;
    block_on(session.handle(StrictClientMessage::Event(event)));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { event_id: id, status: false, message }))
            if id == event_id && message.starts_with("auth-required:")
    ));
    let state = store.0.lock().unwrap();
    assert_eq!(state.query_calls, 0);
    assert_eq!(state.put_calls, 0);
}

#[test]
fn sequential_auth_adds_keys_but_invalid_auth_revokes_and_rotates() {
    let store = FakeStore::default();
    let (hub, mut session) = new_session(store.clone(), limits());
    let first_challenge = expect_initial_challenge(&mut session);
    let first = keys(0x11);
    let second = keys(0x22);

    authenticate(&mut session, &first);
    authenticate(&mut session, &second);
    assert_eq!(
        session.authenticated_keys(),
        &BTreeSet::from([first.public_key(), second.public_key()])
    );
    assert_eq!(session.challenge(), first_challenge);

    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("profiles"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    drain(&mut session);
    assert_eq!(hub.subscription_count(session.token()), 1);

    block_on(session.handle(StrictClientMessage::Auth(auth(&first, "wrong-challenge"))));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: false, message, .. }))
            if message.starts_with("invalid:")
    ));
    let Some(SessionOutput::Send(RelayMessage::Auth { challenge })) = session.next_output() else {
        panic!("invalid AUTH must issue a replacement challenge")
    };
    assert_ne!(challenge.as_ref(), first_challenge);
    assert!(session.authenticated_keys().is_empty());
    assert_eq!(hub.subscription_count(session.token()), 0);

    block_on(session.handle(StrictClientMessage::Auth(auth(&first, &first_challenge))));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: false, .. }))
    ));
    assert!(session.authenticated_keys().is_empty());
    let state = store.0.lock().unwrap();
    assert_eq!(state.put_calls, 0, "AUTH events must never enter storage");
}

#[test]
fn invalid_auth_purges_pending_subscription_data_before_rechallenging() {
    let store = FakeStore::default();
    let (hub, mut session) = new_session(store.clone(), limits());
    expect_initial_challenge(&mut session);
    let account = keys(0x11);
    authenticate(&mut session, &account);
    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("profiles"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    drain(&mut session);

    block_on(session.handle(StrictClientMessage::Event(metadata(
        &account,
        "queued-secret",
    ))));
    block_on(session.handle(StrictClientMessage::Auth(auth(&account, "invalid"))));
    let outputs = drain(&mut session);

    assert!(matches!(
        outputs.as_slice(),
        [
            SessionOutput::Send(RelayMessage::Ok { status: false, .. }),
            SessionOutput::Send(RelayMessage::Auth { .. })
        ]
    ));
    assert_eq!(hub.subscription_count(session.token()), 0);
    assert_eq!(store.0.lock().unwrap().put_calls, 1);
}

#[test]
fn authenticated_req_replaces_and_closes_subscriptions_with_limits() {
    let store = FakeStore::default();
    let historical = metadata(&keys(0x44), r#"{"name":"public"}"#);
    store.0.lock().unwrap().seeded.push(historical.clone());
    let (hub, mut session) = new_session(store, limits());
    expect_initial_challenge(&mut session);
    authenticate(&mut session, &keys(0x11));
    let profiles = SubscriptionId::new("profiles");

    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: profiles.clone(),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    let outputs = drain(&mut session);
    assert!(matches!(
        outputs.as_slice(),
        [
            SessionOutput::Send(RelayMessage::Event { subscription_id, event }),
            SessionOutput::Send(RelayMessage::EndOfStoredEvents(eose_id))
        ] if subscription_id.as_ref() == &profiles
            && event.id == historical.id
            && eose_id.as_ref() == &profiles
    ));

    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: profiles.clone(),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    drain(&mut session);
    assert_eq!(hub.subscription_count(session.token()), 1);

    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("second"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Closed { message, .. }))
            if message.starts_with("rate-limited:")
    ));
    assert_eq!(hub.subscription_count(session.token()), 1);

    block_on(session.handle(StrictClientMessage::Close(profiles)));
    assert_eq!(hub.subscription_count(session.token()), 0);
}

#[test]
fn rejected_replacement_removes_the_old_subscription_atomically() {
    let store = FakeStore::default();
    let (hub, mut session) = new_session(store, limits());
    expect_initial_challenge(&mut session);
    let account = keys(0x11);
    authenticate(&mut session, &account);
    let id = SubscriptionId::new("same-id");
    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: id.clone(),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    drain(&mut session);

    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: id.clone(),
        filters: vec![
            Filter::new().kind(Kind::Metadata),
            Filter::new().kind(Kind::GiftWrap),
        ],
    }));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Closed { subscription_id, message }))
            if subscription_id.as_ref() == &id && message.starts_with("restricted:")
    ));
    assert_eq!(hub.subscription_count(session.token()), 0);
}

#[test]
fn authenticated_publish_returns_ok_and_duplicate_is_idempotent() {
    let store = FakeStore::default();
    let (_hub, mut session) = new_session(store.clone(), limits());
    expect_initial_challenge(&mut session);
    let account = keys(0x11);
    authenticate(&mut session, &account);
    let event = metadata(&account, "{}");

    block_on(session.handle(StrictClientMessage::Event(event.clone())));
    block_on(session.handle(StrictClientMessage::Event(event.clone())));
    let outputs = drain(&mut session);
    assert_eq!(
        outputs
            .iter()
            .filter(|output| matches!(
                output,
                SessionOutput::Send(RelayMessage::Ok { event_id, status: true, .. })
                    if *event_id == event.id
            ))
            .count(),
        2
    );
    assert!(outputs.iter().any(|output| matches!(
        output,
        SessionOutput::Send(RelayMessage::Ok { status: true, message, .. })
            if message.starts_with("duplicate:")
    )));
    let state = store.0.lock().unwrap();
    assert_eq!(state.put_calls, 2);
    assert_eq!(state.stored.len(), 1);
}

#[test]
fn authenticated_author_policy_failure_uses_restricted_prefix() {
    let store = FakeStore::default();
    let (_hub, mut session) = new_session(store, limits());
    expect_initial_challenge(&mut session);
    authenticate(&mut session, &keys(0x11));
    let event = metadata(&keys(0x22), "{}");

    block_on(session.handle(StrictClientMessage::Event(event)));

    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: false, message, .. }))
            if message.starts_with("restricted:")
    ));
}

#[test]
fn pending_query_consumes_budget_until_completion_then_releases_permit() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut session = Session::new(
        hub.clone(),
        relay_url(),
        FixedClock,
        CounterSource(1),
        SessionLimits {
            max_subscriptions: 2,
            max_history_events: 16,
            max_pending_outputs: 16,
            max_in_flight_tasks: 1,
        },
    );
    expect_initial_challenge(&mut session);
    authenticate(&mut session, &keys(0x11));
    let (started, release) = store.gate_next_query();
    let pending = session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("pending"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    let worker = thread::spawn(move || block_on(pending));
    block_on(started).unwrap();
    assert_eq!(session.in_flight_tasks(), 1);

    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("rejected"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Closed { message, .. }))
            if message.starts_with("rate-limited:")
    ));
    assert_eq!(store.0.lock().unwrap().query_calls, 1);
    assert_eq!(hub.subscription_count(session.token()), 1);

    release.send(()).unwrap();
    worker.join().unwrap();
    drain(&mut session);
    assert_eq!(session.in_flight_tasks(), 0);
    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("accepted"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    }));
    assert_eq!(store.0.lock().unwrap().query_calls, 2);
}

#[test]
fn pending_write_budget_survives_disconnect_and_rejects_without_put() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut session = Session::new(
        hub,
        relay_url(),
        FixedClock,
        CounterSource(1),
        SessionLimits {
            max_subscriptions: 1,
            max_history_events: 16,
            max_pending_outputs: 16,
            max_in_flight_tasks: 1,
        },
    );
    expect_initial_challenge(&mut session);
    let account = keys(0x11);
    authenticate(&mut session, &account);
    let (started, release) = store.gate_next_put();
    let pending = session.handle(StrictClientMessage::Event(metadata(&account, "pending")));
    let worker = thread::spawn(move || block_on(pending));
    block_on(started).unwrap();

    block_on(session.handle(StrictClientMessage::Event(metadata(&account, "rejected"))));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: false, message, .. }))
            if message.starts_with("rate-limited:")
    ));
    assert_eq!(store.0.lock().unwrap().put_calls, 1);
    session.disconnect();
    assert_eq!(session.in_flight_tasks(), 1);

    release.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(session.in_flight_tasks(), 0);
}

#[test]
fn invalid_auth_does_not_refund_a_pending_task_budget() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut session = Session::new(
        hub,
        relay_url(),
        FixedClock,
        CounterSource(1),
        SessionLimits {
            max_subscriptions: 1,
            max_history_events: 16,
            max_pending_outputs: 16,
            max_in_flight_tasks: 1,
        },
    );
    expect_initial_challenge(&mut session);
    let account = keys(0x11);
    authenticate(&mut session, &account);
    let (started, release) = store.gate_next_query();
    let pending = session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("pending"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    let worker = thread::spawn(move || block_on(pending));
    block_on(started).unwrap();

    block_on(session.handle(StrictClientMessage::Auth(auth(&account, "wrong"))));
    assert_eq!(session.in_flight_tasks(), 1);
    release.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(session.in_flight_tasks(), 0);
}

#[test]
fn dropping_an_unpolled_task_releases_its_permit() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut session = Session::new(
        hub,
        relay_url(),
        FixedClock,
        CounterSource(1),
        SessionLimits {
            max_subscriptions: 1,
            max_history_events: 16,
            max_pending_outputs: 16,
            max_in_flight_tasks: 1,
        },
    );
    expect_initial_challenge(&mut session);
    let account = keys(0x11);
    authenticate(&mut session, &account);

    let abandoned = session.handle(StrictClientMessage::Event(metadata(&account, "abandoned")));
    assert_eq!(session.in_flight_tasks(), 1);
    assert_eq!(store.0.lock().unwrap().put_calls, 0);
    drop(abandoned);
    assert_eq!(session.in_flight_tasks(), 0);

    block_on(session.handle(StrictClientMessage::Event(metadata(&account, "accepted"))));
    assert_eq!(store.0.lock().unwrap().put_calls, 1);
}

#[test]
fn dropping_an_unpolled_req_removes_its_catching_up_subscription() {
    let store = FakeStore::default();
    let (hub, mut session) = new_session(store.clone(), limits());
    expect_initial_challenge(&mut session);
    authenticate(&mut session, &keys(0x11));

    let abandoned = session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("abandoned"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    assert_eq!(hub.subscription_count(session.token()), 1);
    assert_eq!(session.in_flight_tasks(), 1);
    assert_eq!(store.0.lock().unwrap().query_calls, 0);

    drop(abandoned);

    assert_eq!(hub.subscription_count(session.token()), 0);
    assert_eq!(session.in_flight_tasks(), 0);
}

#[test]
fn dropping_a_polled_pending_req_aborts_query_and_unregisters_it() {
    let store = FakeStore::default();
    let (hub, mut session) = new_session(store.clone(), limits());
    expect_initial_challenge(&mut session);
    authenticate(&mut session, &keys(0x11));
    let (started, release) = store.gate_next_query();
    let mut pending = session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("pending"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
    block_on(started).unwrap();

    drop(pending);

    assert_eq!(hub.subscription_count(session.token()), 0);
    assert_eq!(session.in_flight_tasks(), 0);
    assert!(
        release.send(()).is_err(),
        "dropping the task must abort its query"
    );
}

#[test]
fn cancelled_store_error_cannot_remove_a_newer_subscription_generation() {
    let store = FakeStore::default();
    let (hub, mut session) = new_session(store.clone(), limits());
    expect_initial_challenge(&mut session);
    authenticate(&mut session, &keys(0x11));
    store.fail_next_query();
    let (started, release) = store.gate_next_query();
    let mut old = session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("same-id"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(matches!(old.as_mut().poll(&mut context), Poll::Pending));
    block_on(started).unwrap();

    let replacement = session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("same-id"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    assert_eq!(hub.subscription_count(session.token()), 1);
    release.send(()).unwrap();
    block_on(old);

    assert_eq!(hub.subscription_count(session.token()), 1);
    assert!(drain(&mut session).is_empty());
    drop(replacement);
    assert_eq!(hub.subscription_count(session.token()), 0);
}

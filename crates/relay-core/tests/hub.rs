use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    thread,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use deaddrop_protocol_core::{AuthorizedQuery, ValidatedEvent};
use deaddrop_relay_core::{
    ChallengeSource, Clock, CloseReason, RelayHub, Session, SessionLimits, SessionOutput, Store,
    StoreFuture, StoreOutcome, StrictClientMessage,
};
use futures::{channel::oneshot, executor::block_on, task::noop_waker_ref};
use nostr::{
    Alphabet, Event, EventBuilder, Filter, Keys, Kind, RelayMessage, RelayUrl, SingleLetterTag,
    SubscriptionId, Tag, Timestamp,
};

const NOW: u64 = 1_700_000_000;

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now_seconds(&self) -> u64 {
        NOW
    }
}

struct FixedSource(u8);

impl ChallengeSource for FixedSource {
    fn fill(&mut self, output: &mut [u8]) {
        output.fill(self.0);
    }
}

struct RecordingSource(Arc<AtomicUsize>);

impl ChallengeSource for RecordingSource {
    fn fill(&mut self, output: &mut [u8]) {
        self.0.store(output.len(), Ordering::SeqCst);
        output.fill(0xaa);
    }
}

#[derive(Default)]
struct State {
    history: Vec<Event>,
    stored: Vec<Event>,
    query_calls: usize,
    last_max_results: Option<usize>,
    next_outcome: Option<StoreOutcome>,
    query_gate: Option<Arc<QueryGate>>,
    put_gate: Option<Arc<QueryGate>>,
    reflect_put_in_history: bool,
}

struct QueryGate {
    started: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

#[derive(Clone, Default)]
struct FakeStore(Arc<Mutex<State>>);

impl Store for FakeStore {
    type Error = Infallible;

    fn query<'a>(
        &'a self,
        _queries: &'a [AuthorizedQuery],
        _now_seconds: u64,
        max_results: usize,
    ) -> StoreFuture<'a, Result<Vec<Event>, Self::Error>> {
        Box::pin(async move {
            let (history, gate) = {
                let mut state = self.0.lock().unwrap();
                state.query_calls += 1;
                state.last_max_results = Some(max_results);
                (state.history.clone(), state.query_gate.take())
            };
            await_gate(gate).await;
            Ok(history)
        })
    }

    fn put(&self, event: ValidatedEvent) -> StoreFuture<'_, Result<StoreOutcome, Self::Error>> {
        Box::pin(async move {
            let (outcome, gate) = {
                let mut state = self.0.lock().unwrap();
                let outcome = if let Some(outcome) = state.next_outcome.take() {
                    outcome
                } else if state
                    .stored
                    .iter()
                    .chain(&state.history)
                    .any(|known| known.id == event.event().id)
                {
                    StoreOutcome::Duplicate
                } else {
                    state.stored.push(event.event().clone());
                    if state.reflect_put_in_history {
                        state.history.push(event.event().clone());
                    }
                    StoreOutcome::Stored
                };
                (outcome, state.put_gate.take())
            };
            await_gate(gate).await;
            Ok(outcome)
        })
    }
}

async fn await_gate(gate: Option<Arc<QueryGate>>) {
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

    fn gate_next_put_visible_in_history(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let mut state = self.0.lock().unwrap();
        state.reflect_put_in_history = true;
        install_gate(&mut state.put_gate)
    }
}

fn install_gate(slot: &mut Option<Arc<QueryGate>>) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    *slot = Some(Arc::new(QueryGate {
        started: Mutex::new(Some(started_tx)),
        release: Mutex::new(Some(release_rx)),
    }));
    (started_rx, release_tx)
}

type TestSession = Session<FakeStore, FixedClock, FixedSource>;

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

fn text_note(keys: &Keys) -> Event {
    EventBuilder::new(Kind::TextNote, "not relay-readable")
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(keys)
        .unwrap()
}

fn tag(values: &[&str]) -> Tag {
    Tag::parse(values.iter().copied()).unwrap()
}

fn gift_wrap(keys: &Keys, recipient: &Keys) -> Event {
    let mut payload = vec![0_u8; 99];
    payload[0] = 0x02;
    EventBuilder::new(Kind::GiftWrap, BASE64_STANDARD.encode(payload))
        .tag(tag(&["p", &recipient.public_key().to_hex()]))
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(keys)
        .unwrap()
}

fn group_message(keys: &Keys, route: &str) -> Event {
    EventBuilder::new(Kind::MlsGroupMessage, BASE64_STANDARD.encode([0_u8; 28]))
        .tag(tag(&["h", route]))
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

fn session(hub: &RelayHub<FakeStore>, output_capacity: usize, source: u8) -> TestSession {
    let mut session = Session::new(
        hub.clone(),
        relay_url(),
        FixedClock,
        FixedSource(source),
        SessionLimits {
            max_subscriptions: 4,
            max_history_events: 32,
            max_pending_outputs: output_capacity,
            max_in_flight_tasks: 8,
        },
    );
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Auth { .. }))
    ));
    session
}

fn authenticate(session: &mut TestSession, account: &Keys) {
    let challenge = session.challenge().to_owned();
    block_on(session.handle(StrictClientMessage::Auth(auth(account, &challenge))));
    assert!(matches!(
        session.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: true, .. }))
    ));
}

fn subscribe(session: &mut TestSession, id: &str, filters: Vec<Filter>) {
    block_on(session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new(id),
        filters,
    }));
}

fn drain(session: &mut TestSession) -> Vec<SessionOutput> {
    std::iter::from_fn(|| session.next_output()).collect()
}

fn begin_pending_subscription(
    store: &FakeStore,
    session: &mut TestSession,
    id: &str,
    filters: Vec<Filter>,
) -> (thread::JoinHandle<()>, oneshot::Sender<()>) {
    let (started, release) = store.gate_next_query();
    let task = session.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new(id),
        filters,
    });
    let worker = thread::spawn(move || block_on(task));
    block_on(started).expect("pending store query must start");
    (worker, release)
}

fn event_ids(outputs: &[SessionOutput]) -> Vec<nostr::EventId> {
    outputs
        .iter()
        .filter_map(|output| match output {
            SessionOutput::Send(RelayMessage::Event { event, .. }) => Some(event.id),
            _ => None,
        })
        .collect()
}

#[test]
fn connection_challenges_are_unique_even_when_sources_repeat() {
    let hub = RelayHub::new(FakeStore::default());
    let first = session(&hub, 8, 0xaa);
    let second = session(&hub, 8, 0xaa);

    assert_ne!(first.challenge(), second.challenge());
    assert_eq!(first.challenge().len(), 64);
    assert_eq!(second.challenge().len(), 64);
}

#[test]
fn challenge_uses_all_source_bytes_and_hides_the_uniqueness_nonce() {
    let observed = Arc::new(AtomicUsize::new(0));
    let mut connection = Session::new(
        RelayHub::new(FakeStore::default()),
        relay_url(),
        FixedClock,
        RecordingSource(Arc::clone(&observed)),
        SessionLimits::default(),
    );
    let challenge = connection.challenge().to_owned();

    assert_eq!(observed.load(Ordering::SeqCst), 32);
    assert_eq!(challenge.len(), 64);
    assert!(!challenge.ends_with("0000000000000001"));
    assert!(matches!(
        connection.next_output(),
        Some(SessionOutput::Send(RelayMessage::Auth { .. }))
    ));
}

#[test]
fn auth_event_cannot_be_replayed_on_another_connection() {
    let hub = RelayHub::new(FakeStore::default());
    let mut first = session(&hub, 8, 0xaa);
    let mut second = session(&hub, 8, 0xaa);
    let account = keys(0x11);
    let replay = auth(&account, first.challenge());
    let second_original = second.challenge().to_owned();

    block_on(first.handle(StrictClientMessage::Auth(replay.clone())));
    assert!(matches!(
        first.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: true, .. }))
    ));
    block_on(second.handle(StrictClientMessage::Auth(replay)));
    assert!(matches!(
        second.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: false, .. }))
    ));
    assert_ne!(second.challenge(), second_original);
    assert!(second.authenticated_keys().is_empty());
}

#[test]
fn successful_auth_is_never_stored_or_fanned_out() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    let mut authenticating_peer = session(&hub, 8, 2);
    authenticate(&mut reader, &keys(0x11));
    subscribe(
        &mut reader,
        "profiles",
        vec![Filter::new().kind(Kind::Metadata)],
    );
    drain(&mut reader);

    authenticate(&mut authenticating_peer, &keys(0x22));

    assert!(drain(&mut reader).is_empty());
    assert!(store.0.lock().unwrap().stored.is_empty());
}

#[test]
fn history_defensively_filters_unauthorized_rows_and_deduplicates_before_eose() {
    let store = FakeStore::default();
    let author = keys(0x22);
    let allowed = metadata(&author, r#"{"name":"allowed"}"#);
    let wrong_author = metadata(&keys(0x33), r#"{"name":"wrong"}"#);
    store.0.lock().unwrap().history = vec![
        text_note(&author),
        wrong_author,
        allowed.clone(),
        allowed.clone(),
    ];
    let hub = RelayHub::new(store);
    let mut reader = session(&hub, 8, 1);
    authenticate(&mut reader, &keys(0x11));

    subscribe(
        &mut reader,
        "history",
        vec![
            Filter::new()
                .kind(Kind::Metadata)
                .author(author.public_key()),
        ],
    );
    let outputs = drain(&mut reader);

    assert_eq!(event_ids(&outputs), vec![allowed.id]);
    assert!(matches!(
        outputs.last(),
        Some(SessionOutput::Send(RelayMessage::EndOfStoredEvents(id)))
            if id.as_ref() == &SubscriptionId::new("history")
    ));
}

#[test]
fn history_rejects_poisoned_duplicate_or_malformed_private_routes() {
    let store = FakeStore::default();
    let recipient = keys(0x11);
    let disposable = keys(0x44);
    let recipient_hex = recipient.public_key().to_hex();
    let mut payload = vec![0_u8; 99];
    payload[0] = 0x02;
    let poisoned = EventBuilder::new(Kind::GiftWrap, BASE64_STANDARD.encode(payload))
        .tags([
            tag(&["p", &recipient_hex]),
            tag(&["p", &keys(0x22).public_key().to_hex()]),
        ])
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(&disposable)
        .unwrap();
    assert_eq!(poisoned.tags.len(), 2);
    let malformed = EventBuilder::new(Kind::GiftWrap, gift_wrap(&disposable, &recipient).content)
        .tag(tag(&["p", &recipient_hex, "not-a-relay-url"]))
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(&disposable)
        .unwrap();
    let wrong_route = EventBuilder::new(Kind::GiftWrap, gift_wrap(&disposable, &recipient).content)
        .tags([
            tag(&["p", &recipient_hex]),
            tag(&[
                "h",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ]),
        ])
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(&disposable)
        .unwrap();
    store.0.lock().unwrap().history = vec![poisoned, malformed, wrong_route];
    let hub = RelayHub::new(store);
    let mut reader = session(&hub, 8, 1);
    authenticate(&mut reader, &recipient);

    subscribe(
        &mut reader,
        "inbox",
        vec![
            Filter::new()
                .kind(Kind::GiftWrap)
                .custom_tag(SingleLetterTag::lowercase(Alphabet::P), recipient_hex),
        ],
    );

    assert!(event_ids(&drain(&mut reader)).is_empty());
}

#[test]
fn history_output_and_store_request_are_bounded_by_the_session_limit() {
    let store = FakeStore::default();
    let author = keys(0x22);
    store.0.lock().unwrap().history = vec![
        metadata(&author, "one"),
        metadata(&author, "two"),
        metadata(&author, "three"),
    ];
    let hub = RelayHub::new(store.clone());
    let mut reader = Session::new(
        hub,
        relay_url(),
        FixedClock,
        FixedSource(1),
        SessionLimits {
            max_subscriptions: 1,
            max_history_events: 2,
            max_pending_outputs: 8,
            max_in_flight_tasks: 8,
        },
    );
    reader.next_output();
    authenticate(&mut reader, &keys(0x11));

    subscribe(
        &mut reader,
        "bounded",
        vec![Filter::new().kind(Kind::Metadata)],
    );
    let outputs = drain(&mut reader);

    assert_eq!(event_ids(&outputs).len(), 2);
    assert!(matches!(
        outputs.last(),
        Some(SessionOutput::Send(RelayMessage::EndOfStoredEvents(_)))
    ));
    assert_eq!(store.0.lock().unwrap().last_max_results, Some(2));
}

#[test]
fn history_reserves_queue_space_for_eose_and_control_output() {
    let store = FakeStore::default();
    let author = keys(0x22);
    store.0.lock().unwrap().history = vec![
        metadata(&author, "one"),
        metadata(&author, "two"),
        metadata(&author, "three"),
    ];
    let hub = RelayHub::new(store);
    let mut reader = Session::new(
        hub,
        relay_url(),
        FixedClock,
        FixedSource(1),
        SessionLimits {
            max_subscriptions: 1,
            max_history_events: 32,
            max_pending_outputs: 3,
            max_in_flight_tasks: 8,
        },
    );
    reader.next_output();
    authenticate(&mut reader, &keys(0x11));
    subscribe(
        &mut reader,
        "bounded",
        vec![Filter::new().kind(Kind::Metadata)],
    );
    let outputs = drain(&mut reader);

    assert!(!reader.is_closed());
    assert_eq!(event_ids(&outputs).len(), 1);
    assert!(matches!(
        outputs.last(),
        Some(SessionOutput::Send(RelayMessage::EndOfStoredEvents(_)))
    ));
}

#[test]
fn history_defensively_enforces_each_authorized_filter_limit() {
    let store = FakeStore::default();
    let author = keys(0x22);
    store.0.lock().unwrap().history = vec![
        metadata(&author, "one"),
        metadata(&author, "two"),
        metadata(&author, "three"),
    ];
    let hub = RelayHub::new(store);
    let mut reader = session(&hub, 8, 1);
    authenticate(&mut reader, &keys(0x11));

    subscribe(
        &mut reader,
        "filter-limit",
        vec![Filter::new().kind(Kind::Metadata).limit(1)],
    );

    assert_eq!(event_ids(&drain(&mut reader)).len(), 1);
}

#[test]
fn whole_or_filter_is_rejected_before_store_when_later_member_is_unauthorized() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    let account = keys(0x11);
    authenticate(&mut reader, &account);

    subscribe(
        &mut reader,
        "or",
        vec![
            Filter::new().kind(Kind::Metadata),
            Filter::new().kind(Kind::GiftWrap).custom_tag(
                SingleLetterTag::lowercase(Alphabet::P),
                keys(0x22).public_key().to_hex(),
            ),
        ],
    );

    assert!(matches!(
        reader.next_output(),
        Some(SessionOutput::Send(RelayMessage::Closed { message, .. }))
            if message.starts_with("restricted:")
    ));
    assert_eq!(store.0.lock().unwrap().query_calls, 0);
    assert_eq!(hub.subscription_count(reader.token()), 0);
}

#[test]
fn stored_publish_fans_out_across_sessions_once_for_overlapping_or_filters() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store);
    let mut reader = session(&hub, 8, 1);
    let mut writer = session(&hub, 8, 2);
    authenticate(&mut reader, &keys(0x11));
    let writer_keys = keys(0x22);
    authenticate(&mut writer, &writer_keys);

    subscribe(
        &mut reader,
        "live",
        vec![
            Filter::new().kind(Kind::Metadata),
            Filter::new().kinds([Kind::Metadata, Kind::Custom(30_443)]),
        ],
    );
    assert!(matches!(
        reader.next_output(),
        Some(SessionOutput::Send(RelayMessage::EndOfStoredEvents(_)))
    ));
    let event = metadata(&writer_keys, "{}");
    block_on(writer.handle(StrictClientMessage::Event(event.clone())));

    assert_eq!(event_ids(&drain(&mut reader)), vec![event.id]);
    assert!(matches!(
        writer.next_output(),
        Some(SessionOutput::Send(RelayMessage::Ok { status: true, .. }))
    ));
}

#[test]
fn replacing_a_subscription_removes_its_previous_live_query() {
    let hub = RelayHub::new(FakeStore::default());
    let mut reader = session(&hub, 8, 1);
    let mut writer = session(&hub, 8, 2);
    let writer_keys = keys(0x22);
    authenticate(&mut reader, &keys(0x11));
    authenticate(&mut writer, &writer_keys);
    subscribe(
        &mut reader,
        "replace",
        vec![
            Filter::new()
                .kind(Kind::Metadata)
                .author(writer_keys.public_key()),
        ],
    );
    drain(&mut reader);
    subscribe(
        &mut reader,
        "replace",
        vec![
            Filter::new()
                .kind(Kind::Metadata)
                .author(keys(0x44).public_key()),
        ],
    );
    drain(&mut reader);

    block_on(writer.handle(StrictClientMessage::Event(metadata(&writer_keys, "{}"))));

    assert!(drain(&mut reader).is_empty());
    assert_eq!(hub.subscription_count(reader.token()), 1);
}

#[test]
fn private_live_fanout_requires_the_exact_recipient_or_group_capability() {
    const GROUP_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const GROUP_B: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let hub = RelayHub::new(FakeStore::default());
    let alice_keys = keys(0x11);
    let bob_keys = keys(0x22);
    let writer_keys = keys(0x33);
    let disposable = keys(0x44);
    let mut alice = session(&hub, 16, 1);
    let mut bob = session(&hub, 16, 2);
    let mut writer = session(&hub, 16, 3);
    authenticate(&mut alice, &alice_keys);
    authenticate(&mut bob, &bob_keys);
    authenticate(&mut writer, &writer_keys);
    subscribe(
        &mut alice,
        "alice-inbox",
        vec![Filter::new().kind(Kind::GiftWrap).custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            alice_keys.public_key().to_hex(),
        )],
    );
    subscribe(
        &mut bob,
        "bob-inbox",
        vec![Filter::new().kind(Kind::GiftWrap).custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            bob_keys.public_key().to_hex(),
        )],
    );
    subscribe(
        &mut alice,
        "group-a",
        vec![
            Filter::new()
                .kind(Kind::MlsGroupMessage)
                .custom_tag(SingleLetterTag::lowercase(Alphabet::H), GROUP_A),
        ],
    );
    subscribe(
        &mut bob,
        "group-b",
        vec![
            Filter::new()
                .kind(Kind::MlsGroupMessage)
                .custom_tag(SingleLetterTag::lowercase(Alphabet::H), GROUP_B),
        ],
    );
    drain(&mut alice);
    drain(&mut bob);

    let inbox = gift_wrap(&disposable, &alice_keys);
    let group = group_message(&disposable, GROUP_A);
    block_on(writer.handle(StrictClientMessage::Event(inbox.clone())));
    block_on(writer.handle(StrictClientMessage::Event(group.clone())));
    drain(&mut writer);

    assert_eq!(event_ids(&drain(&mut alice)), vec![inbox.id, group.id]);
    assert!(drain(&mut bob).is_empty());
}

#[test]
fn duplicate_store_outcome_after_history_never_fans_out() {
    let store = FakeStore::default();
    let writer_keys = keys(0x22);
    let event = metadata(&writer_keys, "{}");
    {
        let mut state = store.0.lock().unwrap();
        state.history.push(event.clone());
    }
    let hub = RelayHub::new(store);
    let mut reader = session(&hub, 8, 1);
    let mut writer = session(&hub, 8, 2);
    authenticate(&mut reader, &keys(0x11));
    authenticate(&mut writer, &writer_keys);
    subscribe(
        &mut reader,
        "handoff",
        vec![Filter::new().kind(Kind::Metadata)],
    );

    let history = drain(&mut reader);
    assert_eq!(event_ids(&history), vec![event.id]);
    assert!(matches!(
        history.last(),
        Some(SessionOutput::Send(RelayMessage::EndOfStoredEvents(_)))
    ));
    block_on(writer.handle(StrictClientMessage::Event(event)));
    assert!(drain(&mut reader).is_empty());
}

#[test]
fn committed_put_and_new_subscription_are_serialized_for_exactly_once_delivery() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    let mut writer = session(&hub, 8, 2);
    authenticate(&mut reader, &keys(0x11));
    let writer_keys = keys(0x22);
    authenticate(&mut writer, &writer_keys);
    let event = metadata(&writer_keys, "committed-before-put-returns");
    let (put_committed, release_put) = store.gate_next_put_visible_in_history();

    let publish = writer.handle(StrictClientMessage::Event(event.clone()));
    let publish_worker = thread::spawn(move || block_on(publish));
    block_on(put_committed).expect("the fake store must visibly commit before returning");

    let mut subscribe = reader.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("handoff"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(
        matches!(subscribe.as_mut().poll(&mut context), Poll::Pending),
        "the subscription query must wait for the committed publish's fan-out"
    );

    release_put.send(()).unwrap();
    publish_worker.join().unwrap();
    block_on(subscribe);

    let outputs = drain(&mut reader);
    assert_eq!(event_ids(&outputs), vec![event.id]);
    assert!(matches!(
        outputs.last(),
        Some(SessionOutput::Send(RelayMessage::EndOfStoredEvents(_)))
    ));
}

#[test]
fn publish_during_pending_history_is_buffered_after_eose_and_deduplicated() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    let mut writer = session(&hub, 8, 2);
    authenticate(&mut reader, &keys(0x11));
    let writer_keys = keys(0x22);
    authenticate(&mut writer, &writer_keys);
    let (pending, release) = begin_pending_subscription(
        &store,
        &mut reader,
        "handoff",
        vec![Filter::new().kind(Kind::Metadata)],
    );
    let event = metadata(&writer_keys, "during-catchup");

    let publish = writer.handle(StrictClientMessage::Event(event.clone()));
    let publish_worker = thread::spawn(move || block_on(publish));
    assert!(drain(&mut reader).is_empty());
    release.send(()).unwrap();
    pending.join().unwrap();
    publish_worker.join().unwrap();
    let outputs = drain(&mut reader);

    assert!(matches!(
        outputs.first(),
        Some(SessionOutput::Send(RelayMessage::EndOfStoredEvents(_)))
    ));
    assert_eq!(event_ids(&outputs), vec![event.id]);
}

#[test]
fn replacement_while_history_is_pending_discards_the_stale_completion() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    authenticate(&mut reader, &keys(0x11));
    let (pending, release) = begin_pending_subscription(
        &store,
        &mut reader,
        "replace",
        vec![Filter::new().kind(Kind::Metadata)],
    );

    let (replacement_started, release_replacement) = store.gate_next_query();
    let replacement = reader.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("replace"),
        filters: vec![
            Filter::new()
                .kind(Kind::Metadata)
                .author(keys(0x22).public_key()),
        ],
    });
    let replacement = thread::spawn(move || block_on(replacement));
    release.send(()).unwrap();
    pending.join().unwrap();
    assert!(drain(&mut reader).is_empty());
    assert_eq!(hub.subscription_count(reader.token()), 1);

    block_on(replacement_started).expect("replacement query must start after stale completion");
    release_replacement.send(()).unwrap();
    replacement.join().unwrap();
    let replacement_outputs = drain(&mut reader);
    assert_eq!(replacement_outputs.len(), 1);
    assert!(matches!(
        replacement_outputs[0],
        SessionOutput::Send(RelayMessage::EndOfStoredEvents(_))
    ));
}

#[test]
fn close_while_history_is_pending_discards_event_and_eose() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    authenticate(&mut reader, &keys(0x11));
    let (pending, release) = begin_pending_subscription(
        &store,
        &mut reader,
        "close",
        vec![Filter::new().kind(Kind::Metadata)],
    );

    block_on(reader.handle(StrictClientMessage::Close(SubscriptionId::new("close"))));
    release.send(()).unwrap();
    pending.join().unwrap();

    assert!(drain(&mut reader).is_empty());
    assert_eq!(hub.subscription_count(reader.token()), 0);
}

#[test]
fn disconnect_while_history_is_pending_discards_the_completion() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    authenticate(&mut reader, &keys(0x11));
    let token = reader.token();
    let (pending, release) = begin_pending_subscription(
        &store,
        &mut reader,
        "disconnect",
        vec![Filter::new().kind(Kind::Metadata)],
    );

    reader.disconnect();
    release.send(()).unwrap();
    pending.join().unwrap();

    assert_eq!(hub.subscription_count(token), 0);
    assert!(reader.next_output().is_none());
}

#[test]
fn invalid_auth_while_history_is_pending_revokes_before_stale_completion() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let account = keys(0x11);
    let mut reader = session(&hub, 8, 1);
    authenticate(&mut reader, &account);
    let (pending, release) = begin_pending_subscription(
        &store,
        &mut reader,
        "revoked",
        vec![Filter::new().kind(Kind::Metadata)],
    );

    block_on(reader.handle(StrictClientMessage::Auth(auth(&account, "wrong"))));
    let revoke_outputs = drain(&mut reader);
    assert!(matches!(
        revoke_outputs.as_slice(),
        [
            SessionOutput::Send(RelayMessage::Ok { status: false, message, .. }),
            SessionOutput::Send(RelayMessage::Auth { .. })
        ] if message.starts_with("invalid:")
    ));
    release.send(()).unwrap();
    pending.join().unwrap();

    assert!(drain(&mut reader).is_empty());
    assert_eq!(hub.subscription_count(reader.token()), 0);
}

#[test]
fn catchup_buffer_overflow_closes_only_the_slow_session() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut fast = session(&hub, 16, 1);
    let mut slow = session(&hub, 2, 2);
    let mut writer = session(&hub, 16, 3);
    authenticate(&mut fast, &keys(0x11));
    authenticate(&mut slow, &keys(0x22));
    let writer_keys = keys(0x33);
    authenticate(&mut writer, &writer_keys);
    subscribe(&mut fast, "fast", vec![Filter::new().kind(Kind::Metadata)]);
    drain(&mut fast);
    let event = metadata(&writer_keys, "one");
    let (put_committed, release) = store.gate_next_put_visible_in_history();
    let publish = writer.handle(StrictClientMessage::Event(event));
    let publish = thread::spawn(move || block_on(publish));
    block_on(put_committed).unwrap();
    let pending = slow.handle(StrictClientMessage::Req {
        subscription_id: SubscriptionId::new("slow"),
        filters: vec![Filter::new().kind(Kind::Metadata)],
    });
    assert!(!fast.is_closed());
    release.send(()).unwrap();
    publish.join().unwrap();
    assert!(slow.is_closed());
    block_on(pending);

    assert!(matches!(
        slow.next_output(),
        Some(SessionOutput::Close(CloseReason::SlowConsumer))
    ));
    assert_eq!(event_ids(&drain(&mut fast)).len(), 1);
}

#[test]
fn superseded_replaceable_is_acknowledged_without_live_fanout() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store.clone());
    let mut reader = session(&hub, 8, 1);
    let mut writer = session(&hub, 8, 2);
    authenticate(&mut reader, &keys(0x11));
    let writer_keys = keys(0x22);
    authenticate(&mut writer, &writer_keys);
    subscribe(
        &mut reader,
        "profiles",
        vec![Filter::new().kind(Kind::Metadata)],
    );
    drain(&mut reader);
    store.0.lock().unwrap().next_outcome = Some(StoreOutcome::Superseded);

    block_on(writer.handle(StrictClientMessage::Event(metadata(&writer_keys, "older"))));
    let writer_outputs = drain(&mut writer);

    assert!(drain(&mut reader).is_empty());
    assert!(matches!(
        writer_outputs.as_slice(),
        [SessionOutput::Send(RelayMessage::Ok { status: true, message, .. })]
            if message.starts_with("duplicate:")
    ));
}

#[test]
fn slow_consumer_closes_and_unregisters_without_affecting_fast_peer() {
    let store = FakeStore::default();
    let hub = RelayHub::new(store);
    let mut slow = session(&hub, 2, 1);
    let mut fast = session(&hub, 16, 2);
    let mut writer = session(&hub, 16, 3);
    authenticate(&mut slow, &keys(0x11));
    authenticate(&mut fast, &keys(0x22));
    let writer_keys = keys(0x33);
    authenticate(&mut writer, &writer_keys);
    subscribe(&mut slow, "slow", vec![Filter::new().kind(Kind::Metadata)]);
    subscribe(&mut fast, "fast", vec![Filter::new().kind(Kind::Metadata)]);
    drain(&mut slow);
    drain(&mut fast);

    let events = [
        metadata(&writer_keys, "one"),
        metadata(&writer_keys, "two"),
        metadata(&writer_keys, "three"),
    ];
    for event in &events {
        block_on(writer.handle(StrictClientMessage::Event(event.clone())));
        drain(&mut writer);
    }

    assert!(slow.is_closed());
    assert_eq!(hub.subscription_count(slow.token()), 0);
    assert!(matches!(
        slow.next_output(),
        Some(SessionOutput::Close(CloseReason::SlowConsumer))
    ));
    assert!(!fast.is_closed());
    assert_eq!(event_ids(&drain(&mut fast)).len(), 3);
}

#[test]
fn disconnect_unregisters_all_subscriptions() {
    let hub = RelayHub::new(FakeStore::default());
    let token;
    {
        let mut reader = session(&hub, 8, 1);
        authenticate(&mut reader, &keys(0x11));
        subscribe(
            &mut reader,
            "profiles",
            vec![Filter::new().kind(Kind::Metadata)],
        );
        drain(&mut reader);
        token = reader.token();
        assert_eq!(hub.subscription_count(token), 1);
    }
    assert_eq!(hub.subscription_count(token), 0);
}

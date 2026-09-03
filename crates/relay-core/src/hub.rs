use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

use deaddrop_protocol_core::{AuthorizedQuery, AuthorizedScope, ValidatedEvent};
use futures::lock::Mutex as AsyncMutex;
use nostr::{
    Event, RelayMessage, RelayUrl, SubscriptionId,
    hashes::{Hash as _, sha256},
};

use crate::{ChallengeSource, Store, StoreOutcome};

/// Opaque identity for one live relay connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionToken(u64);

/// A policy-approved subscription. Its fields cannot be fabricated downstream.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedSubscription {
    id: SubscriptionId,
    queries: Vec<AuthorizedQuery>,
    generation: u64,
}

impl AuthorizedSubscription {
    pub(crate) fn new(id: SubscriptionId, queries: Vec<AuthorizedQuery>, generation: u64) -> Self {
        Self {
            id,
            queries,
            generation,
        }
    }

    pub fn id(&self) -> &SubscriptionId {
        &self.id
    }

    pub fn queries(&self) -> &[AuthorizedQuery] {
        &self.queries
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for AuthorizedSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedSubscription")
            .field("id", &self.id)
            .field("query_count", &self.queries.len())
            .field("generation", &self.generation)
            .finish()
    }
}

/// Why the socket owner must close a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    SlowConsumer,
    StorageFailure,
}

/// One action or outbound message produced by a session.
pub enum SessionOutput {
    Send(RelayMessage<'static>),
    Subscribe(AuthorizedSubscription),
    Unsubscribe(SubscriptionId),
    Publish(ValidatedEvent),
    Close(CloseReason),
}

impl fmt::Debug for SessionOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(RelayMessage::Event {
                subscription_id, ..
            }) => formatter
                .debug_struct("SendEvent")
                .field("subscription_id", subscription_id)
                .field("event", &"[redacted]")
                .finish(),
            Self::Send(RelayMessage::Auth { .. }) => formatter.write_str("SendAuth([redacted])"),
            Self::Send(message) => formatter.debug_tuple("Send").field(message).finish(),
            Self::Subscribe(subscription) => formatter
                .debug_tuple("Subscribe")
                .field(subscription)
                .finish(),
            Self::Unsubscribe(id) => formatter.debug_tuple("Unsubscribe").field(id).finish(),
            Self::Publish(event) => formatter.debug_tuple("Publish").field(event).finish(),
            Self::Close(reason) => formatter.debug_tuple("Close").field(reason).finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionPhase {
    CatchingUp,
    Live,
}

struct RegisteredSubscription {
    authorized: AuthorizedSubscription,
    phase: SubscriptionPhase,
    buffered_live: Vec<Event>,
}

struct HubSession {
    output_capacity: usize,
    outputs: VecDeque<SessionOutput>,
    subscriptions: BTreeMap<SubscriptionId, RegisteredSubscription>,
    closed: Option<CloseReason>,
}

struct HubState {
    sessions: BTreeMap<SessionToken, HubSession>,
    next_session: u64,
    next_challenge: u64,
}

pub(crate) struct PendingSubscription {
    token: SessionToken,
    subscription_id: SubscriptionId,
    queries: Vec<AuthorizedQuery>,
    generation: u64,
    now_seconds: u64,
    snapshot_limit: usize,
}

/// Shared store, subscription registry, and bounded live fan-out coordinator.
pub struct RelayHub<S> {
    inner: Arc<Mutex<HubState>>,
    store: Arc<S>,
    operation_gate: Arc<AsyncMutex<()>>,
}

impl<S> Clone for RelayHub<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            store: Arc::clone(&self.store),
            operation_gate: Arc::clone(&self.operation_gate),
        }
    }
}

impl<S> RelayHub<S> {
    pub fn new(store: S) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubState {
                sessions: BTreeMap::new(),
                next_session: 0,
                next_challenge: 0,
            })),
            store: Arc::new(store),
            operation_gate: Arc::new(AsyncMutex::new(())),
        }
    }

    pub(crate) fn register(&self, output_capacity: usize) -> SessionToken {
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");
        state.next_session = state.next_session.wrapping_add(1);
        let token = SessionToken(state.next_session);
        state.sessions.insert(
            token,
            HubSession {
                output_capacity,
                outputs: VecDeque::new(),
                subscriptions: BTreeMap::new(),
                closed: None,
            },
        );
        token
    }

    pub(crate) fn issue_challenge<R: ChallengeSource>(&self, source: &mut R) -> String {
        let mut entropy = [0_u8; 32];
        source.fill(&mut entropy);
        let nonce = {
            let mut state = self.inner.lock().expect("relay hub mutex poisoned");
            state.next_challenge = state.next_challenge.wrapping_add(1);
            state.next_challenge
        };
        let mut input = [0_u8; 40];
        input[..32].copy_from_slice(&entropy);
        input[32..].copy_from_slice(&nonce.to_be_bytes());
        encode_lower_hex(&sha256::Hash::hash(&input).to_byte_array())
    }

    pub(crate) fn enqueue(&self, token: SessionToken, output: SessionOutput) -> bool {
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");
        enqueue_locked(&mut state, token, output)
    }

    pub(crate) fn pop_output(&self, token: SessionToken) -> Option<SessionOutput> {
        self.inner
            .lock()
            .expect("relay hub mutex poisoned")
            .sessions
            .get_mut(&token)
            .and_then(|session| session.outputs.pop_front())
    }

    pub(crate) fn is_closed(&self, token: SessionToken) -> bool {
        self.inner
            .lock()
            .expect("relay hub mutex poisoned")
            .sessions
            .get(&token)
            .is_none_or(|session| session.closed.is_some())
    }

    pub fn subscription_count(&self, token: SessionToken) -> usize {
        self.inner
            .lock()
            .expect("relay hub mutex poisoned")
            .sessions
            .get(&token)
            .map_or(0, |session| session.subscriptions.len())
    }

    pub(crate) fn unsubscribe(&self, token: SessionToken, id: &SubscriptionId) {
        if let Some(session) = self
            .inner
            .lock()
            .expect("relay hub mutex poisoned")
            .sessions
            .get_mut(&token)
        {
            session.subscriptions.remove(id);
        }
    }

    pub(crate) fn cancel_catchup(&self, token: SessionToken, id: &SubscriptionId, generation: u64) {
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");
        let matches = state
            .sessions
            .get(&token)
            .and_then(|session| session.subscriptions.get(id))
            .is_some_and(|registered| {
                registered.authorized.generation == generation
                    && registered.phase == SubscriptionPhase::CatchingUp
            });
        if matches && let Some(session) = state.sessions.get_mut(&token) {
            session.subscriptions.remove(id);
        }
    }

    pub(crate) fn revoke_and_enqueue(&self, token: SessionToken, outputs: [SessionOutput; 2]) {
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");
        if let Some(session) = state.sessions.get_mut(&token) {
            session.subscriptions.clear();
            session.outputs.clear();
        }
        for output in outputs {
            enqueue_locked(&mut state, token, output);
        }
    }

    pub(crate) fn disconnect(&self, token: SessionToken) {
        self.inner
            .lock()
            .expect("relay hub mutex poisoned")
            .sessions
            .remove(&token);
    }
}

impl<S: Store> RelayHub<S> {
    pub(crate) fn begin_subscribe(
        &self,
        token: SessionToken,
        subscription: AuthorizedSubscription,
        now_seconds: u64,
        max_history_events: usize,
    ) -> Option<PendingSubscription> {
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");
        let id = subscription.id.clone();
        let queries = subscription.queries.clone();
        let generation = subscription.generation;
        let session = state.sessions.get_mut(&token)?;
        session.subscriptions.insert(
            id.clone(),
            RegisteredSubscription {
                authorized: subscription,
                phase: SubscriptionPhase::CatchingUp,
                buffered_live: Vec::new(),
            },
        );
        let snapshot_limit = max_history_events.min(available_history_slots(session, &id));
        if reserved_catchup_load(session) > session.output_capacity {
            close_slow_locked(&mut state, token);
            return None;
        }
        Some(PendingSubscription {
            token,
            subscription_id: id,
            queries,
            generation,
            now_seconds,
            snapshot_limit,
        })
    }

    pub(crate) async fn finish_subscribe(
        &self,
        pending: PendingSubscription,
    ) -> Result<bool, S::Error> {
        if !self.is_current_catchup(&pending) {
            return Ok(false);
        }
        let _operation = self.operation_gate.lock().await;
        if !self.is_current_catchup(&pending) {
            return Ok(false);
        }
        let raw_history = self
            .store
            .query(
                &pending.queries,
                pending.now_seconds,
                pending.snapshot_limit,
            )
            .await?;
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");
        let Some(session) = state.sessions.get(&pending.token) else {
            return Ok(false);
        };
        let Some(registered) = session.subscriptions.get(&pending.subscription_id) else {
            return Ok(false);
        };
        if registered.authorized.generation != pending.generation
            || registered.phase != SubscriptionPhase::CatchingUp
        {
            return Ok(false);
        }

        let available_history =
            available_history_slots(session, &pending.subscription_id).min(pending.snapshot_limit);
        let history = bounded_history(&pending.queries, raw_history, available_history);
        let mut handoff_ids = BTreeSet::new();

        for event in history {
            handoff_ids.insert(event.id);
            if !enqueue_locked(
                &mut state,
                pending.token,
                SessionOutput::Send(RelayMessage::event(pending.subscription_id.clone(), event)),
            ) {
                return Ok(false);
            }
        }

        if !enqueue_locked(
            &mut state,
            pending.token,
            SessionOutput::Send(RelayMessage::eose(pending.subscription_id.clone())),
        ) {
            return Ok(false);
        }

        let buffered = state
            .sessions
            .get_mut(&pending.token)
            .and_then(|session| session.subscriptions.get_mut(&pending.subscription_id))
            .filter(|registered| registered.authorized.generation == pending.generation)
            .map(|registered| {
                registered.phase = SubscriptionPhase::Live;
                core::mem::take(&mut registered.buffered_live)
            })
            .unwrap_or_default();
        for event in buffered {
            if handoff_ids.insert(event.id) {
                enqueue_locked(
                    &mut state,
                    pending.token,
                    SessionOutput::Send(RelayMessage::event(
                        pending.subscription_id.clone(),
                        event,
                    )),
                );
            }
        }
        Ok(true)
    }

    pub(crate) fn fail_subscription(
        &self,
        token: SessionToken,
        id: SubscriptionId,
        generation: u64,
    ) {
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");
        let matches = state
            .sessions
            .get(&token)
            .and_then(|session| session.subscriptions.get(&id))
            .is_some_and(|registered| registered.authorized.generation == generation);
        if matches {
            if let Some(session) = state.sessions.get_mut(&token) {
                session.subscriptions.remove(&id);
            }
            enqueue_locked(
                &mut state,
                token,
                SessionOutput::Send(RelayMessage::closed(id, "error: storage failure")),
            );
        }
    }

    pub(crate) async fn publish(&self, event: ValidatedEvent) -> Result<StoreOutcome, S::Error> {
        let _operation = self.operation_gate.lock().await;
        let raw = event.event().clone();
        let outcome = self.store.put(event).await?;
        if outcome != StoreOutcome::Stored {
            return Ok(outcome);
        }
        let mut state = self.inner.lock().expect("relay hub mutex poisoned");

        let targets = state
            .sessions
            .iter()
            .flat_map(|(token, session)| {
                session
                    .subscriptions
                    .iter()
                    .filter(|(_, registered)| {
                        registered
                            .authorized
                            .queries
                            .iter()
                            .any(|query| query_matches(query, &raw))
                    })
                    .map(|(id, _)| (*token, id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for (token, id) in targets {
            let phase = state
                .sessions
                .get(&token)
                .and_then(|session| session.subscriptions.get(&id))
                .map(|registered| registered.phase);
            match phase {
                Some(SubscriptionPhase::CatchingUp) => {
                    let duplicate = state
                        .sessions
                        .get(&token)
                        .and_then(|session| session.subscriptions.get(&id))
                        .is_some_and(|registered| {
                            registered
                                .buffered_live
                                .iter()
                                .any(|buffered| buffered.id == raw.id)
                        });
                    if duplicate {
                        continue;
                    }
                    let full = state.sessions.get(&token).is_some_and(|session| {
                        reserved_catchup_load(session) >= session.output_capacity
                    });
                    if full {
                        close_slow_locked(&mut state, token);
                    } else if let Some(registered) = state
                        .sessions
                        .get_mut(&token)
                        .and_then(|session| session.subscriptions.get_mut(&id))
                    {
                        registered.buffered_live.push(raw.clone());
                    }
                }
                Some(SubscriptionPhase::Live) => {
                    enqueue_locked(
                        &mut state,
                        token,
                        SessionOutput::Send(RelayMessage::event(id, raw.clone())),
                    );
                }
                None => {}
            }
        }
        Ok(outcome)
    }

    fn is_current_catchup(&self, pending: &PendingSubscription) -> bool {
        self.inner
            .lock()
            .expect("relay hub mutex poisoned")
            .sessions
            .get(&pending.token)
            .and_then(|session| session.subscriptions.get(&pending.subscription_id))
            .is_some_and(|registered| {
                registered.authorized.generation == pending.generation
                    && registered.phase == SubscriptionPhase::CatchingUp
            })
    }
}

fn enqueue_locked(state: &mut HubState, token: SessionToken, output: SessionOutput) -> bool {
    let Some(session) = state.sessions.get_mut(&token) else {
        return false;
    };
    if session.closed.is_some() {
        return false;
    }
    if session.outputs.len() >= session.output_capacity {
        close_slow_locked(state, token);
        return false;
    }
    session.outputs.push_back(output);
    true
}

fn close_slow_locked(state: &mut HubState, token: SessionToken) {
    if let Some(session) = state.sessions.get_mut(&token) {
        session.closed = Some(CloseReason::SlowConsumer);
        session.subscriptions.clear();
        session.outputs.clear();
        session
            .outputs
            .push_back(SessionOutput::Close(CloseReason::SlowConsumer));
    }
}

fn reserved_catchup_load(session: &HubSession) -> usize {
    let catchups = session
        .subscriptions
        .values()
        .filter(|registered| registered.phase == SubscriptionPhase::CatchingUp)
        .count();
    let buffered = session
        .subscriptions
        .values()
        .map(|registered| registered.buffered_live.len())
        .sum::<usize>();
    session
        .outputs
        .len()
        .saturating_add(catchups)
        .saturating_add(buffered)
        .saturating_add(1)
}

fn available_history_slots(session: &HubSession, current: &SubscriptionId) -> usize {
    let other_catchups = session
        .subscriptions
        .iter()
        .filter(|(id, registered)| {
            *id != current && registered.phase == SubscriptionPhase::CatchingUp
        })
        .count();
    let buffered = session
        .subscriptions
        .values()
        .map(|registered| registered.buffered_live.len())
        .sum::<usize>();
    session
        .output_capacity
        .saturating_sub(session.outputs.len())
        .saturating_sub(other_catchups)
        .saturating_sub(buffered)
        .saturating_sub(2)
}

fn query_matches(query: &AuthorizedQuery, event: &Event) -> bool {
    if !query.kinds().contains(&event.kind)
        || query.ids().is_some_and(|ids| !ids.contains(&event.id))
        || query
            .authors()
            .is_some_and(|authors| !authors.contains(&event.pubkey))
        || query.since().is_some_and(|since| event.created_at < since)
        || query.until().is_some_and(|until| event.created_at > until)
    {
        return false;
    }
    match query.scope() {
        AuthorizedScope::Public => true,
        AuthorizedScope::Inbox(recipient) => {
            exact_private_route(event, "p", &recipient.to_hex(), true)
        }
        AuthorizedScope::Group(capability) => {
            exact_private_route(event, "h", &encode_lower_hex(capability), false)
        }
    }
}

fn exact_private_route(event: &Event, name: &str, expected: &str, relay_hint: bool) -> bool {
    if event.tags.iter().any(|tag| {
        tag.as_slice()
            .first()
            .is_some_and(|actual| matches!(actual.as_str(), "d" | "p" | "h") && actual != name)
    }) {
        return false;
    }
    let mut routes = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|actual| actual == name));
    let Some(route) = routes.next() else {
        return false;
    };
    if routes.next().is_some() {
        return false;
    }
    let values = route.as_slice();
    let valid_shape = values.len() == 2
        || (relay_hint && values.len() == 3 && RelayUrl::parse(&values[2]).is_ok());
    valid_shape && values[1] == expected
}

fn bounded_history(
    queries: &[AuthorizedQuery],
    events: Vec<Event>,
    max_results: usize,
) -> Vec<Event> {
    let mut selected = Vec::with_capacity(max_results.min(events.len()));
    let mut delivered = BTreeSet::new();
    let mut query_counts = vec![0_usize; queries.len()];
    for event in events {
        if selected.len() == max_results {
            break;
        }
        if delivered.contains(&event.id) {
            continue;
        }
        let matching = queries
            .iter()
            .enumerate()
            .filter(|(index, query)| {
                query_matches(query, &event)
                    && query
                        .limit()
                        .is_none_or(|limit| query_counts[*index] < limit)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        for index in matching {
            query_counts[index] += 1;
        }
        delivered.insert(event.id);
        selected.push(event);
    }
    selected
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

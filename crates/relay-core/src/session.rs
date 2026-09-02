use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use deaddrop_protocol_core::{EventPolicyError, authorize_filters, validate_write};
use nostr::{EventId, PublicKey, RelayMessage, RelayUrl, SubscriptionId};

use crate::{
    AuthorizedSubscription, PlatformSendSync, RelayHub, SessionOutput, SessionToken, Store,
    StoreOutcome, StrictClientMessage, validate_auth_event,
};

#[cfg(not(target_arch = "wasm32"))]
/// Detached store work produced by [`Session::handle`].
pub type SessionTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[cfg(target_arch = "wasm32")]
/// Detached store work produced by [`Session::handle`].
pub type SessionTask = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// Deterministic resource limits applied to one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    pub max_subscriptions: usize,
    pub max_history_events: usize,
    pub max_pending_outputs: usize,
    pub max_in_flight_tasks: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_subscriptions: 32,
            max_history_events: 1_000,
            max_pending_outputs: 256,
            max_in_flight_tasks: 32,
        }
    }
}

/// Trusted relay time used by authentication, write policy, and storage reads.
pub trait Clock {
    fn now_seconds(&self) -> u64;
}

/// Cryptographically secure byte source supplied by the hosting environment.
pub trait ChallengeSource {
    fn fill(&mut self, output: &mut [u8]);
}

/// State machine for exactly one authenticated Nostr connection.
pub struct Session<S, C, R> {
    hub: RelayHub<S>,
    token: SessionToken,
    relay_url: RelayUrl,
    clock: C,
    challenge_source: R,
    challenge: String,
    authenticated_keys: BTreeSet<PublicKey>,
    next_subscription_generation: u64,
    limits: SessionLimits,
    in_flight_tasks: Arc<AtomicUsize>,
    disconnected: bool,
}

struct TaskPermit {
    in_flight_tasks: Arc<AtomicUsize>,
}

struct SubscriptionTaskGuard<S> {
    hub: RelayHub<S>,
    token: SessionToken,
    subscription_id: SubscriptionId,
    generation: u64,
    armed: bool,
}

impl<S> SubscriptionTaskGuard<S> {
    fn new(
        hub: RelayHub<S>,
        token: SessionToken,
        subscription_id: SubscriptionId,
        generation: u64,
    ) -> Self {
        Self {
            hub,
            token,
            subscription_id,
            generation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<S> Drop for SubscriptionTaskGuard<S> {
    fn drop(&mut self) {
        if self.armed {
            self.hub
                .cancel_catchup(self.token, &self.subscription_id, self.generation);
        }
    }
}

impl Drop for TaskPermit {
    fn drop(&mut self) {
        self.in_flight_tasks.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<S, C, R> Session<S, C, R>
where
    C: Clock,
    R: ChallengeSource,
{
    pub fn new(
        hub: RelayHub<S>,
        relay_url: RelayUrl,
        clock: C,
        mut challenge_source: R,
        limits: SessionLimits,
    ) -> Self {
        assert!(limits.max_pending_outputs >= 2);
        assert!(limits.max_subscriptions > 0);
        assert!(limits.max_history_events > 0);
        assert!(limits.max_in_flight_tasks > 0);
        let token = hub.register(limits.max_pending_outputs);
        let challenge = hub.issue_challenge(&mut challenge_source);
        hub.enqueue(
            token,
            SessionOutput::Send(RelayMessage::auth(challenge.clone())),
        );
        Self {
            hub,
            token,
            relay_url,
            clock,
            challenge_source,
            challenge,
            authenticated_keys: BTreeSet::new(),
            next_subscription_generation: 0,
            limits,
            in_flight_tasks: Arc::new(AtomicUsize::new(0)),
            disconnected: false,
        }
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    pub fn authenticated_keys(&self) -> &BTreeSet<PublicKey> {
        &self.authenticated_keys
    }

    pub fn token(&self) -> SessionToken {
        self.token
    }

    pub fn next_output(&mut self) -> Option<SessionOutput> {
        self.hub.pop_output(self.token)
    }

    pub fn is_closed(&self) -> bool {
        self.hub.is_closed(self.token)
    }

    pub fn in_flight_tasks(&self) -> usize {
        self.in_flight_tasks.load(Ordering::Acquire)
    }

    pub fn disconnect(&mut self) {
        if !self.disconnected {
            self.hub.disconnect(self.token);
            self.disconnected = true;
        }
    }

    fn send(&self, message: RelayMessage<'static>) {
        self.hub.enqueue(self.token, SessionOutput::Send(message));
    }

    fn rotate_challenge(&mut self) {
        self.challenge = self.hub.issue_challenge(&mut self.challenge_source);
    }

    fn reject_auth(&mut self, event_id: EventId) {
        self.authenticated_keys.clear();
        self.rotate_challenge();
        self.hub.revoke_and_enqueue(
            self.token,
            [
                SessionOutput::Send(RelayMessage::ok(
                    event_id,
                    false,
                    "invalid: authentication rejected",
                )),
                SessionOutput::Send(RelayMessage::auth(self.challenge.clone())),
            ],
        );
    }

    fn try_task_permit(&self) -> Option<TaskPermit> {
        self.in_flight_tasks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.limits.max_in_flight_tasks).then_some(current + 1)
            })
            .ok()?;
        Some(TaskPermit {
            in_flight_tasks: Arc::clone(&self.in_flight_tasks),
        })
    }
}

impl<S, C, R> Session<S, C, R>
where
    S: Store,
    C: Clock,
    R: ChallengeSource,
{
    /// Apply the synchronous connection-state transition and return any store
    /// work that must be driven to completion.
    ///
    /// The task owns no borrow of this session. A connection driver may keep
    /// polling it while applying later CLOSE, replacement REQ, disconnect, or
    /// AUTH transitions; generation checks discard stale completions.
    #[must_use = "the returned store task must be driven to completion"]
    pub fn handle(&mut self, message: StrictClientMessage) -> SessionTask
    where
        S: PlatformSendSync + 'static,
    {
        if self.disconnected || self.is_closed() {
            return ready_task();
        }
        match message {
            StrictClientMessage::Auth(event) => {
                match validate_auth_event(
                    &event,
                    &self.relay_url,
                    &self.challenge,
                    self.clock.now_seconds(),
                ) {
                    Ok(public_key) => {
                        self.authenticated_keys.insert(public_key);
                        self.send(RelayMessage::ok(event.id, true, "authenticated"));
                    }
                    Err(_) => self.reject_auth(event.id),
                }
                ready_task()
            }
            StrictClientMessage::Req {
                subscription_id,
                filters,
            } => {
                if self.authenticated_keys.is_empty() {
                    self.send(RelayMessage::closed(
                        subscription_id,
                        "auth-required: authenticate before REQ",
                    ));
                    return ready_task();
                }

                // A reused ID always terminates the previous subscription, even
                // when its replacement fails authorization.
                self.hub.unsubscribe(self.token, &subscription_id);
                let Some(permit) = self.try_task_permit() else {
                    self.send(RelayMessage::closed(
                        subscription_id,
                        "rate-limited: too many in-flight operations",
                    ));
                    return ready_task();
                };
                let queries = match authorize_filters(&self.authenticated_keys, &filters) {
                    Ok(queries) => queries,
                    Err(_) => {
                        self.send(RelayMessage::closed(
                            subscription_id,
                            "restricted: filter is not authorized",
                        ));
                        return ready_task();
                    }
                };
                if self.hub.subscription_count(self.token) >= self.limits.max_subscriptions {
                    self.send(RelayMessage::closed(
                        subscription_id,
                        "rate-limited: too many subscriptions",
                    ));
                    return ready_task();
                }

                self.next_subscription_generation =
                    self.next_subscription_generation.wrapping_add(1);
                let subscription = AuthorizedSubscription::new(
                    subscription_id.clone(),
                    queries,
                    self.next_subscription_generation,
                );
                let generation = self.next_subscription_generation;
                let Some(pending) = self.hub.begin_subscribe(
                    self.token,
                    subscription,
                    self.clock.now_seconds(),
                    self.limits.max_history_events,
                ) else {
                    return ready_task();
                };
                let hub = self.hub.clone();
                let token = self.token;
                let mut cancellation = SubscriptionTaskGuard::new(
                    hub.clone(),
                    token,
                    subscription_id.clone(),
                    generation,
                );
                Box::pin(async move {
                    let _permit = permit;
                    match hub.finish_subscribe(pending).await {
                        Ok(true) => cancellation.disarm(),
                        Ok(false) => {}
                        Err(_) => {
                            hub.fail_subscription(token, subscription_id, generation);
                            cancellation.disarm();
                        }
                    }
                })
            }
            StrictClientMessage::Close(subscription_id) => {
                self.hub.unsubscribe(self.token, &subscription_id);
                ready_task()
            }
            StrictClientMessage::Event(event) => {
                let event_id = event.id;
                if self.authenticated_keys.is_empty() {
                    self.send(RelayMessage::ok(
                        event_id,
                        false,
                        "auth-required: authenticate before EVENT",
                    ));
                    return ready_task();
                }
                let Some(permit) = self.try_task_permit() else {
                    self.send(RelayMessage::ok(
                        event_id,
                        false,
                        "rate-limited: too many in-flight operations",
                    ));
                    return ready_task();
                };
                let validated =
                    match validate_write(&self.authenticated_keys, self.clock.now_seconds(), event)
                    {
                        Ok(validated) => validated,
                        Err(error) => {
                            let message = match error {
                                EventPolicyError::Unauthenticated
                                | EventPolicyError::UnauthorizedAuthor => {
                                    "restricted: event author is not authorized"
                                }
                                _ => "invalid: event rejected",
                            };
                            self.send(RelayMessage::ok(event_id, false, message));
                            return ready_task();
                        }
                    };
                let hub = self.hub.clone();
                let token = self.token;
                Box::pin(async move {
                    let _permit = permit;
                    let response = match hub.publish(validated).await {
                        Ok(StoreOutcome::Stored) => RelayMessage::ok(event_id, true, "stored"),
                        Ok(StoreOutcome::Duplicate) => {
                            RelayMessage::ok(event_id, true, "duplicate: already stored")
                        }
                        Ok(StoreOutcome::Superseded) => {
                            RelayMessage::ok(event_id, true, "duplicate: superseded")
                        }
                        Err(_) => RelayMessage::ok(event_id, false, "error: storage failure"),
                    };
                    hub.enqueue(token, SessionOutput::Send(response));
                })
            }
        }
    }
}

fn ready_task() -> SessionTask {
    Box::pin(async {})
}

impl<S, C, R> Drop for Session<S, C, R> {
    fn drop(&mut self) {
        if !self.disconnected {
            self.hub.disconnect(self.token);
            self.disconnected = true;
        }
    }
}

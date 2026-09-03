use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    path::{Component, Path, PathBuf},
    thread,
    time::Duration,
};

use async_channel::{Receiver, Sender, bounded};
use deaddrop_protocol_core::{
    AuthorizedQuery, AuthorizedScope, EventClass, ValidatedEvent, validate_write,
};
use deaddrop_relay_core::StoreOutcome;
use futures::channel::oneshot;
use nostr::{Event, JsonUtil, Kind, RelayUrl};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, named_params, params,
};

use crate::{Error, migrations};

pub(crate) enum Command {
    Query {
        queries: Vec<AuthorizedQuery>,
        now_seconds: u64,
        max_results: usize,
        response: oneshot::Sender<Result<Vec<Event>, Error>>,
    },
    Put {
        event: Box<ValidatedEvent>,
        response: oneshot::Sender<Result<StoreOutcome, Error>>,
    },
    Compact {
        now_seconds: u64,
        response: oneshot::Sender<Result<usize, Error>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), Error>>,
    },
}

pub(crate) type Startup = oneshot::Receiver<Result<(), Error>>;

pub(crate) fn spawn(path: PathBuf, capacity: usize) -> Result<(Sender<Command>, Startup), Error> {
    if capacity == 0 {
        return Err(Error::InvalidQueueCapacity);
    }
    let (sender, receiver) = bounded(capacity);
    let (startup_sender, startup_receiver) = oneshot::channel();
    thread::Builder::new()
        .name("deaddrop-relay-sqlite".to_owned())
        .spawn(move || match open_connection(&path) {
            Ok(connection) => {
                let _ = startup_sender.send(Ok(()));
                run(connection, receiver);
            }
            Err(error) => {
                let _ = startup_sender.send(Err(error));
            }
        })
        .map_err(Error::thread)?;
    Ok((sender, startup_receiver))
}

fn open_connection(path: &PathBuf) -> Result<Connection, Error> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(Error::UnsafeStatePath);
    }
    ensure_private_parent(path)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(Error::io)?;
    restrict_permissions(path)?;
    drop(file);

    let connection = Connection::open(path).map_err(Error::database)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(Error::database)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(Error::database)?;
    let foreign_keys = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
        .map_err(Error::database)?;
    let busy_timeout = connection
        .pragma_query_value(None, "busy_timeout", |row| row.get::<_, i64>(0))
        .map_err(Error::database)?;
    if foreign_keys != 1 || busy_timeout != 5_000 {
        return Err(Error::ConnectionConfiguration);
    }
    migrations::migrate(&connection)?;
    Ok(connection)
}

fn ensure_private_parent(path: &Path) -> Result<(), Error> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(Error::MissingStateDirectory);
    };
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(Error::io)?;
        restrict_directory_permissions(parent)?;
    }
    verify_directory_permissions(parent)
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(Error::io)
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &std::path::Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn verify_directory_permissions(path: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path).map_err(Error::io)?.permissions().mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(Error::InsecureDirectory)
    }
}

#[cfg(not(unix))]
fn verify_directory_permissions(_path: &std::path::Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &PathBuf) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(Error::io)
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &PathBuf) -> Result<(), Error> {
    Ok(())
}

fn run(mut connection: Connection, receiver: Receiver<Command>) {
    while let Ok(command) = receiver.recv_blocking() {
        match command {
            Command::Query {
                queries,
                now_seconds,
                max_results,
                response,
            } => {
                let _ = response.send(query_events(
                    &connection,
                    &queries,
                    now_seconds,
                    max_results,
                ));
            }
            Command::Put { event, response } => {
                let _ = response.send(put_event(&mut connection, *event));
            }
            Command::Compact {
                now_seconds,
                response,
            } => {
                let _ = response.send(compact(&mut connection, now_seconds));
            }
            Command::Shutdown { response } => {
                drop(receiver);
                drop(connection);
                let _ = response.send(Ok(()));
                return;
            }
        }
    }
}

fn put_event(
    connection: &mut Connection,
    validated: ValidatedEvent,
) -> Result<StoreOutcome, Error> {
    let row = InsertRow::from_validated(&validated)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(Error::database)?;
    if transaction
        .query_row("SELECT 1 FROM events WHERE id = ?1", [&row.id], |_| Ok(()))
        .optional()
        .map_err(Error::database)?
        .is_some()
    {
        return Ok(StoreOutcome::Duplicate);
    }

    if let Some(coordinate) = &row.replacement_key
        && let Some((current_id, current_created_at)) = transaction
            .query_row(
                "SELECT id, created_at FROM events WHERE replacement_key = ?1",
                [coordinate],
                |stored| Ok((stored.get::<_, String>(0)?, stored.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(Error::database)?
    {
        let incoming_wins = row.created_at > current_created_at
            || (row.created_at == current_created_at && row.id < current_id);
        if !incoming_wins {
            return Ok(StoreOutcome::Superseded);
        }
        transaction
            .execute(
                "DELETE FROM events WHERE replacement_key = ?1",
                [coordinate],
            )
            .map_err(Error::database)?;
    }

    insert_row(&transaction, &row)?;
    transaction.commit().map_err(Error::database)?;
    Ok(StoreOutcome::Stored)
}

fn insert_row(transaction: &Transaction<'_>, row: &InsertRow) -> Result<(), Error> {
    transaction
        .execute(
            "INSERT INTO events (id, event_json, kind, pubkey, created_at, received_at, d_tag, p_tag, h_tag, expires_at, replacement_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.id,
                row.event_json,
                row.kind,
                row.pubkey,
                row.created_at,
                row.received_at,
                row.d_tag,
                row.p_tag,
                row.h_tag,
                row.expires_at,
                row.replacement_key,
            ],
        )
        .map_err(Error::database)?;
    Ok(())
}

struct InsertRow {
    id: String,
    event_json: String,
    kind: i64,
    pubkey: String,
    created_at: i64,
    received_at: i64,
    d_tag: Option<String>,
    p_tag: Option<String>,
    h_tag: Option<String>,
    expires_at: Option<i64>,
    replacement_key: Option<String>,
}

impl InsertRow {
    fn from_validated(validated: &ValidatedEvent) -> Result<Self, Error> {
        let event = validated.event();
        let pubkey = event.pubkey.to_hex();
        let (d_tag, p_tag, h_tag, replacement_key) = match validated.class() {
            EventClass::Metadata => (None, None, None, Some(format!("0:{pubkey}"))),
            EventClass::KeyPackage { d } => (
                Some(d.clone()),
                None,
                None,
                Some(format!("30443:{pubkey}:{d}")),
            ),
            EventClass::Inbox { recipient } => (None, Some(recipient.to_hex()), None, None),
            EventClass::Group { h } => (None, None, Some(encode_lower_hex(h)), None),
        };
        Ok(Self {
            id: event.id.to_hex(),
            event_json: event.as_json(),
            kind: i64::from(event.kind.as_u16()),
            pubkey,
            created_at: sql_time(event.created_at.as_secs())?,
            received_at: sql_time(validated.received_at())?,
            d_tag,
            p_tag,
            h_tag,
            expires_at: validated.expires_at().map(sql_time).transpose()?,
            replacement_key,
        })
    }
}

fn query_events(
    connection: &Connection,
    queries: &[AuthorizedQuery],
    now_seconds: u64,
    max_results: usize,
) -> Result<Vec<Event>, Error> {
    if max_results == 0 || queries.is_empty() {
        return Ok(Vec::new());
    }
    i64::try_from(max_results).map_err(|_| Error::ResultLimitOutOfRange(max_results))?;
    let now = sql_time(now_seconds)?;
    let mut candidates = BTreeMap::new();
    for query in queries {
        for event in query_candidates(connection, query, now, max_results)? {
            candidates.entry(event.id.to_hex()).or_insert(event);
        }
    }
    let mut candidates = candidates.into_values().collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.id.to_hex().cmp(&right.id.to_hex()))
    });

    let mut selected = Vec::with_capacity(max_results.min(candidates.len()));
    let mut query_counts = vec![0_usize; queries.len()];
    for event in candidates {
        if selected.len() == max_results {
            break;
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
        selected.push(event);
    }
    Ok(selected)
}

fn query_candidates(
    connection: &Connection,
    query: &AuthorizedQuery,
    now: i64,
    max_results: usize,
) -> Result<Vec<Event>, Error> {
    const QUERY: &str = "SELECT id, event_json, kind, pubkey, created_at, received_at, d_tag, p_tag, h_tag, expires_at, replacement_key
        FROM events
        WHERE (expires_at IS NULL OR expires_at > :now)
          AND ((:scope = 0 AND p_tag IS NULL AND h_tag IS NULL)
            OR (:scope = 1 AND p_tag = :route)
            OR (:scope = 2 AND h_tag = :route))
          AND kind IN (SELECT CAST(value AS INTEGER) FROM json_each(:kinds))
          AND (:ids IS NULL OR id IN (SELECT CAST(value AS TEXT) FROM json_each(:ids)))
          AND (:authors IS NULL OR pubkey IN (SELECT CAST(value AS TEXT) FROM json_each(:authors)))
          AND (:since IS NULL OR created_at >= :since)
          AND (:until IS NULL OR created_at <= :until)
        ORDER BY created_at DESC, id ASC
        LIMIT :limit";
    let (scope, route) = match query.scope() {
        AuthorizedScope::Public => (0_i64, None),
        AuthorizedScope::Inbox(recipient) => (1, Some(recipient.to_hex())),
        AuthorizedScope::Group(capability) => (2, Some(encode_lower_hex(capability))),
    };
    let kinds = query
        .kinds()
        .iter()
        .map(|kind| kind.as_u16())
        .collect::<Vec<_>>();
    let kinds =
        serde_json::to_string(&kinds).map_err(|error| Error::Serialization(error.to_string()))?;
    let ids = query
        .ids()
        .map(|ids| ids.iter().map(|id| id.to_hex()).collect::<Vec<_>>())
        .map(|ids| serde_json::to_string(&ids))
        .transpose()
        .map_err(|error| Error::Serialization(error.to_string()))?;
    let authors = query
        .authors()
        .map(|authors| {
            authors
                .iter()
                .map(|author| author.to_hex())
                .collect::<Vec<_>>()
        })
        .map(|authors| serde_json::to_string(&authors))
        .transpose()
        .map_err(|error| Error::Serialization(error.to_string()))?;
    let since = query
        .since()
        .map(|since| sql_time(since.as_secs()))
        .transpose()?;
    let until = query
        .until()
        .map(|until| sql_time(until.as_secs()))
        .transpose()?;
    let query_limit = query.limit().unwrap_or(max_results).min(max_results);
    let query_limit =
        i64::try_from(query_limit).map_err(|_| Error::ResultLimitOutOfRange(query_limit))?;

    let mut statement = connection.prepare(QUERY).map_err(Error::database)?;
    let rows = statement
        .query_map(
            named_params! {
                ":now": now,
                ":scope": scope,
                ":route": route,
                ":kinds": kinds,
                ":ids": ids,
                ":authors": authors,
                ":since": since,
                ":until": until,
                ":limit": query_limit,
            },
            StoredRow::read,
        )
        .map_err(Error::database)?;
    let mut events = Vec::new();
    for row in rows {
        let row = row.map_err(Error::database)?;
        events.push(row.valid_event()?);
    }
    Ok(events)
}

struct StoredRow {
    id: String,
    event_json: String,
    kind: i64,
    pubkey: String,
    created_at: i64,
    received_at: i64,
    d_tag: Option<String>,
    p_tag: Option<String>,
    h_tag: Option<String>,
    expires_at: Option<i64>,
    replacement_key: Option<String>,
}

impl StoredRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            event_json: row.get(1)?,
            kind: row.get(2)?,
            pubkey: row.get(3)?,
            created_at: row.get(4)?,
            received_at: row.get(5)?,
            d_tag: row.get(6)?,
            p_tag: row.get(7)?,
            h_tag: row.get(8)?,
            expires_at: row.get(9)?,
            replacement_key: row.get(10)?,
        })
    }

    fn valid_event(self) -> Result<Event, Error> {
        let event = Event::from_json(&self.event_json).map_err(|_| Error::CorruptRow)?;
        if event.as_json() != self.event_json
            || event.id.to_hex() != self.id
            || i64::from(event.kind.as_u16()) != self.kind
            || event.pubkey.to_hex() != self.pubkey
            || sql_time(event.created_at.as_secs()).map_err(|_| Error::CorruptRow)?
                != self.created_at
        {
            return Err(Error::CorruptRow);
        }
        let received_at = u64::try_from(self.received_at).map_err(|_| Error::CorruptRow)?;
        let validated = validate_write(&BTreeSet::from([event.pubkey]), received_at, event.clone())
            .map_err(|_| Error::CorruptRow)?;
        let expected = InsertRow::from_validated(&validated).map_err(|_| Error::CorruptRow)?;
        if expected.d_tag != self.d_tag
            || expected.p_tag != self.p_tag
            || expected.h_tag != self.h_tag
            || expected.expires_at != self.expires_at
            || expected.replacement_key != self.replacement_key
        {
            return Err(Error::CorruptRow);
        }
        Ok(event)
    }
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
        AuthorizedScope::Public => matches!(event.kind, Kind::Metadata | Kind::Custom(30_443)),
        AuthorizedScope::Inbox(recipient) => exact_route(event, "p", &recipient.to_hex(), true),
        AuthorizedScope::Group(capability) => {
            exact_route(event, "h", &encode_lower_hex(capability), false)
        }
    }
}

fn exact_route(event: &Event, name: &str, expected: &str, relay_hint: bool) -> bool {
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

fn compact(connection: &mut Connection, now_seconds: u64) -> Result<usize, Error> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(Error::database)?;
    let removed = transaction
        .execute(
            "DELETE FROM events WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            [sql_time(now_seconds)?],
        )
        .map_err(Error::database)?;
    transaction.commit().map_err(Error::database)?;
    Ok(removed)
}

fn sql_time(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::TimestampOutOfRange(value))
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

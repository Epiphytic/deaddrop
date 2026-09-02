use std::{
    collections::BTreeSet,
    fs,
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use deaddrop_protocol_core::{AuthorizedQuery, authorize_filters, validate_write};
use deaddrop_relay_core::{Store, StoreOutcome};
use deaddrop_relay_sqlite::{Error, SqliteStore};
use futures::{executor::block_on, task::noop_waker_ref};
use nostr::{
    Alphabet, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, PublicKey, SingleLetterTag, Tag,
    Timestamp,
};
use rusqlite::Connection;
use tempfile::TempDir;

const NOW: u64 = 1_700_000_000;
const DAY: u64 = 24 * 60 * 60;
const GROUP_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GROUP_B: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn keys(byte: u8) -> Keys {
    Keys::parse(&format!("{byte:02x}").repeat(32)).unwrap()
}

fn authenticated(account: &Keys) -> BTreeSet<PublicKey> {
    BTreeSet::from([account.public_key()])
}

fn tag(values: &[&str]) -> Tag {
    Tag::parse(values.iter().copied()).unwrap()
}

fn metadata(account: &Keys, created_at: u64, content: &str) -> Event {
    EventBuilder::new(Kind::Metadata, content)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(account)
        .unwrap()
}

fn metadata_with_d(account: &Keys, created_at: u64, content: &str, d: &str) -> Event {
    EventBuilder::new(Kind::Metadata, content)
        .tag(tag(&["d", d]))
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(account)
        .unwrap()
}

fn key_package(account: &Keys, created_at: u64, d: &str, marker: u8) -> Event {
    EventBuilder::new(Kind::Custom(30_443), BASE64_STANDARD.encode([marker]))
        .tags([
            tag(&["d", d]),
            tag(&["mls_protocol_version", "1.0"]),
            tag(&["i", &format!("{marker:02x}").repeat(32)]),
            tag(&["mls_ciphersuite", "0x0001"]),
            tag(&["mls_extensions", "0x0001"]),
            tag(&["mls_proposals", "0x0002"]),
            tag(&["app_components", "0xf001"]),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(account)
        .unwrap()
}

fn inbox(disposable: &Keys, recipient: &Keys, marker: u8) -> Event {
    let mut payload = vec![0_u8; 99];
    payload[0] = 0x02;
    payload[1] = marker;
    EventBuilder::new(Kind::GiftWrap, BASE64_STANDARD.encode(payload))
        .tag(tag(&["p", &recipient.public_key().to_hex()]))
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(disposable)
        .unwrap()
}

fn group(disposable: &Keys, route: &str, marker: u8) -> Event {
    let mut payload = [0_u8; 28];
    payload[0] = marker;
    EventBuilder::new(Kind::MlsGroupMessage, BASE64_STANDARD.encode(payload))
        .tag(tag(&["h", route]))
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(disposable)
        .unwrap()
}

fn validated(event: Event, authenticated_account: &Keys) -> deaddrop_protocol_core::ValidatedEvent {
    validate_write(&authenticated(authenticated_account), NOW, event).unwrap()
}

fn authorized(account: &Keys, filter: Filter) -> AuthorizedQuery {
    authorize_filters(&authenticated(account), &[filter])
        .unwrap()
        .pop()
        .unwrap()
}

fn open(temp: &TempDir) -> SqliteStore {
    block_on(SqliteStore::open(db_path(temp), 8)).unwrap()
}

fn db_path(temp: &TempDir) -> std::path::PathBuf {
    temp.path().join("state").join("relay.sqlite3")
}

fn put(store: &SqliteStore, event: Event, account: &Keys) -> StoreOutcome {
    block_on(store.put(validated(event, account))).unwrap()
}

fn query(store: &SqliteStore, queries: &[AuthorizedQuery], now: u64) -> Vec<Event> {
    block_on(store.query(queries, now, 100)).unwrap()
}

fn ids(events: &[Event]) -> BTreeSet<String> {
    events.iter().map(|event| event.id.to_hex()).collect()
}

#[test]
fn fresh_migration_records_canonical_json_denormalized_fields_and_restricts_permissions() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    let account = keys(0x11);
    let event = key_package(&account, NOW - 5, "drop", 0x44);

    assert_eq!(put(&store, event.clone(), &account), StoreOutcome::Stored);

    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
    let row = connection
        .query_row(
            "SELECT event_json, kind, pubkey, created_at, received_at, d_tag, p_tag, h_tag, expires_at, replacement_key FROM events WHERE id = ?1",
            [event.id.to_hex()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(row.0, event.as_json());
    assert_eq!(row.1, 30_443);
    assert_eq!(row.2, account.public_key().to_hex());
    assert_eq!(row.3, i64::try_from(NOW - 5).unwrap());
    assert_eq!(row.4, i64::try_from(NOW).unwrap());
    assert_eq!(row.5.as_deref(), Some("drop"));
    assert_eq!(row.6, None);
    assert_eq!(row.7, None);
    assert_eq!(row.8, None);
    assert!(row.9.as_deref().unwrap().ends_with(":drop"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn reopen_preserves_events_and_exact_ids_are_idempotent() {
    let temp = TempDir::new().unwrap();
    let account = keys(0x11);
    let event = metadata(&account, NOW, "persistent");
    {
        let store = open(&temp);
        assert_eq!(put(&store, event.clone(), &account), StoreOutcome::Stored);
        assert_eq!(
            put(&store, event.clone(), &account),
            StoreOutcome::Duplicate
        );
    }

    let reopened = open(&temp);
    let public = authorized(&account, Filter::new().kind(Kind::Metadata));
    assert_eq!(
        ids(&query(&reopened, &[public], NOW)),
        BTreeSet::from([event.id.to_hex()])
    );
}

#[test]
fn queries_enforce_exact_public_inbox_group_and_secondary_constraints() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let other = keys(0x22);
    let disposable = keys(0x33);
    let public = metadata(&other, NOW - 3, "public");
    let alice_inbox = inbox(&disposable, &account, 1);
    let bob_inbox = inbox(&disposable, &other, 2);
    let group_a = group(&disposable, GROUP_A, 3);
    let group_b = group(&disposable, GROUP_B, 4);
    assert_eq!(put(&store, public.clone(), &other), StoreOutcome::Stored);
    for event in [&alice_inbox, &bob_inbox, &group_a, &group_b] {
        assert_eq!(put(&store, event.clone(), &account), StoreOutcome::Stored);
    }

    let public_query = authorized(
        &account,
        Filter::new()
            .kind(Kind::Metadata)
            .author(other.public_key())
            .id(public.id)
            .since(Timestamp::from(NOW - 3))
            .until(Timestamp::from(NOW - 3)),
    );
    let inbox_query = authorized(
        &account,
        Filter::new().kind(Kind::GiftWrap).custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            account.public_key().to_hex(),
        ),
    );
    let group_query = authorized(
        &account,
        Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::H), GROUP_A),
    );

    assert_eq!(query(&store, &[public_query], NOW), vec![public]);
    assert_eq!(query(&store, &[inbox_query], NOW), vec![alice_inbox]);
    assert_eq!(query(&store, &[group_query], NOW), vec![group_a]);
}

fn assert_newer_wins_both_orders(
    make_old: impl Fn() -> Event,
    make_new: impl Fn() -> Event,
    account: &Keys,
    filter: Filter,
) {
    for old_first in [true, false] {
        let temp = TempDir::new().unwrap();
        let store = open(&temp);
        let old = make_old();
        let new = make_new();
        let outcomes = if old_first {
            [put(&store, old, account), put(&store, new.clone(), account)]
        } else {
            [put(&store, new.clone(), account), put(&store, old, account)]
        };
        assert_eq!(outcomes[0], StoreOutcome::Stored);
        assert_eq!(
            outcomes[1],
            if old_first {
                StoreOutcome::Stored
            } else {
                StoreOutcome::Superseded
            }
        );
        let authorized = authorized(account, filter.clone());
        assert_eq!(query(&store, &[authorized], NOW), vec![new]);
    }
}

#[test]
fn newer_metadata_and_key_package_replace_transactionally_in_both_arrival_orders() {
    let account = keys(0x11);
    assert_newer_wins_both_orders(
        || metadata(&account, NOW - 2, "old"),
        || metadata(&account, NOW - 1, "new"),
        &account,
        Filter::new().kind(Kind::Metadata),
    );
    assert_newer_wins_both_orders(
        || key_package(&account, NOW - 2, "drop", 1),
        || key_package(&account, NOW - 1, "drop", 2),
        &account,
        Filter::new().kind(Kind::Custom(30_443)),
    );
}

#[test]
fn replacement_winner_survives_worker_restart() {
    let temp = TempDir::new().unwrap();
    let account = keys(0x11);
    let old = key_package(&account, NOW - 1, "drop", 1);
    let winner = key_package(&account, NOW, "drop", 2);
    {
        let store = open(&temp);
        assert_eq!(put(&store, old, &account), StoreOutcome::Stored);
        assert_eq!(put(&store, winner.clone(), &account), StoreOutcome::Stored);
        block_on(store.shutdown()).unwrap();
    }

    let reopened = open(&temp);
    let packages = authorized(&account, Filter::new().kind(Kind::Custom(30_443)));
    assert_eq!(query(&reopened, &[packages], NOW), vec![winner]);
}

#[test]
fn equal_timestamp_replacement_uses_lexicographically_lower_event_id_in_both_orders() {
    let account = keys(0x11);
    let first = metadata(&account, NOW, "first");
    let second = metadata(&account, NOW, "second");
    let (winner, loser) = if first.id.to_hex() < second.id.to_hex() {
        (first, second)
    } else {
        (second, first)
    };

    for winner_first in [true, false] {
        let temp = TempDir::new().unwrap();
        let store = open(&temp);
        let outcomes = if winner_first {
            [
                put(&store, winner.clone(), &account),
                put(&store, loser.clone(), &account),
            ]
        } else {
            [
                put(&store, loser.clone(), &account),
                put(&store, winner.clone(), &account),
            ]
        };
        assert_eq!(outcomes[0], StoreOutcome::Stored);
        assert_eq!(
            outcomes[1],
            if winner_first {
                StoreOutcome::Superseded
            } else {
                StoreOutcome::Stored
            }
        );
        let public = authorized(&account, Filter::new().kind(Kind::Metadata));
        assert_eq!(query(&store, &[public], NOW), vec![winner.clone()]);
    }
}

#[test]
fn equal_timestamp_key_package_replacement_uses_lower_id_in_both_orders() {
    let account = keys(0x11);
    let first = key_package(&account, NOW, "drop", 1);
    let second = key_package(&account, NOW, "drop", 2);
    let (winner, loser) = if first.id.to_hex() < second.id.to_hex() {
        (first, second)
    } else {
        (second, first)
    };

    for winner_first in [true, false] {
        let temp = TempDir::new().unwrap();
        let store = open(&temp);
        let outcomes = if winner_first {
            [
                put(&store, winner.clone(), &account),
                put(&store, loser.clone(), &account),
            ]
        } else {
            [
                put(&store, loser.clone(), &account),
                put(&store, winner.clone(), &account),
            ]
        };
        assert_eq!(outcomes[0], StoreOutcome::Stored);
        assert_eq!(
            outcomes[1],
            if winner_first {
                StoreOutcome::Superseded
            } else {
                StoreOutcome::Stored
            }
        );
        let public = authorized(&account, Filter::new().kind(Kind::Custom(30_443)));
        assert_eq!(query(&store, &[public], NOW), vec![winner.clone()]);
    }
}

#[test]
fn replacement_coordinates_are_isolated_by_author() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let alice = keys(0x11);
    let bob = keys(0x22);
    let alice_metadata = metadata(&alice, NOW, "alice");
    let bob_metadata = metadata(&bob, NOW, "bob");
    let alice_package = key_package(&alice, NOW, "same-d", 1);
    let bob_package = key_package(&bob, NOW, "same-d", 2);

    for (event, author) in [
        (&alice_metadata, &alice),
        (&bob_metadata, &bob),
        (&alice_package, &alice),
        (&bob_package, &bob),
    ] {
        assert_eq!(put(&store, event.clone(), author), StoreOutcome::Stored);
    }

    let metadata_query = authorized(&alice, Filter::new().kind(Kind::Metadata));
    let package_query = authorized(&alice, Filter::new().kind(Kind::Custom(30_443)));
    assert_eq!(
        ids(&query(&store, &[metadata_query], NOW)),
        ids(&[alice_metadata, bob_metadata])
    );
    assert_eq!(
        ids(&query(&store, &[package_query], NOW)),
        ids(&[alice_package, bob_package])
    );
}

#[test]
fn metadata_ignores_d_tags_while_key_packages_keep_distinct_sealed_coordinates() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let old = metadata_with_d(&account, NOW - 2, "old", "one");
    let new = metadata_with_d(&account, NOW - 1, "new", "two");
    assert_eq!(put(&store, old, &account), StoreOutcome::Stored);
    assert_eq!(put(&store, new.clone(), &account), StoreOutcome::Stored);
    let metadata_query = authorized(&account, Filter::new().kind(Kind::Metadata));
    assert_eq!(query(&store, &[metadata_query], NOW), vec![new]);

    let package_a = key_package(&account, NOW, "a", 1);
    let package_b = key_package(&account, NOW, "b", 2);
    assert_eq!(
        put(&store, package_a.clone(), &account),
        StoreOutcome::Stored
    );
    assert_eq!(
        put(&store, package_b.clone(), &account),
        StoreOutcome::Stored
    );
    let package_query = authorized(&account, Filter::new().kind(Kind::Custom(30_443)));
    assert_eq!(
        ids(&query(&store, &[package_query], NOW)),
        ids(&[package_a, package_b])
    );
}

#[test]
fn multi_filter_union_is_deterministic_with_per_filter_limits_and_final_cap() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let reader = keys(0x11);
    let first_author = keys(0x21);
    let second_author = keys(0x22);
    let third_author = keys(0x23);
    let newest = metadata(&first_author, NOW, "newest");
    let middle = metadata(&second_author, NOW - 1, "middle");
    let oldest = metadata(&third_author, NOW - 2, "oldest");
    for (event, author) in [
        (&newest, &first_author),
        (&middle, &second_author),
        (&oldest, &third_author),
    ] {
        assert_eq!(put(&store, event.clone(), author), StoreOutcome::Stored);
    }
    let newest_only = authorized(&reader, Filter::new().kind(Kind::Metadata).limit(1));
    let second_author_only = authorized(
        &reader,
        Filter::new()
            .kind(Kind::Metadata)
            .author(second_author.public_key())
            .limit(1),
    );

    assert_eq!(
        query(
            &store,
            &[newest_only.clone(), second_author_only.clone()],
            NOW
        ),
        vec![newest.clone(), middle.clone()]
    );
    assert_eq!(
        block_on(store.query(&[newest_only, second_author_only], NOW, 1)).unwrap(),
        vec![newest]
    );
}

#[test]
fn out_of_range_query_time_is_rejected_without_integer_wrapping() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let public = authorized(&account, Filter::new().kind(Kind::Metadata));

    assert!(matches!(
        block_on(store.query(&[public], u64::MAX, 1)),
        Err(Error::TimestampOutOfRange(u64::MAX))
    ));
}

#[test]
fn out_of_range_result_limit_is_rejected_without_integer_wrapping() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let public = authorized(&account, Filter::new().kind(Kind::Metadata));

    assert!(matches!(
        block_on(store.query(std::slice::from_ref(&public), NOW, usize::MAX)),
        Err(Error::ResultLimitOutOfRange(usize::MAX))
    ));
    let limited = authorized(&account, Filter::new().kind(Kind::Metadata).limit(1));
    assert!(matches!(
        block_on(store.query(&[limited], NOW, usize::MAX)),
        Err(Error::ResultLimitOutOfRange(usize::MAX))
    ));
}

#[test]
fn inbox_and_group_events_are_not_replaceable() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let disposable = keys(0x22);
    let inboxes = [
        inbox(&disposable, &account, 1),
        inbox(&disposable, &account, 2),
    ];
    let groups = [
        group(&disposable, GROUP_A, 1),
        group(&disposable, GROUP_A, 2),
    ];
    for event in inboxes.iter().chain(&groups) {
        assert_eq!(put(&store, event.clone(), &account), StoreOutcome::Stored);
    }
    let inbox_query = authorized(
        &account,
        Filter::new().kind(Kind::GiftWrap).custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            account.public_key().to_hex(),
        ),
    );
    let group_query = authorized(
        &account,
        Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::H), GROUP_A),
    );
    assert_eq!(ids(&query(&store, &[inbox_query], NOW)), ids(&inboxes));
    assert_eq!(ids(&query(&store, &[group_query], NOW)), ids(&groups));
}

#[test]
fn replacement_insert_failure_rolls_back_the_deleted_winner() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    let account = keys(0x11);
    let old = metadata(&account, NOW - 2, "old");
    let new = metadata(&account, NOW - 1, "new");
    assert_eq!(put(&store, old.clone(), &account), StoreOutcome::Stored);
    Connection::open(&path)
        .unwrap()
        .execute_batch(&format!(
            "CREATE TRIGGER reject_replacement BEFORE INSERT ON events WHEN NEW.id = '{}' BEGIN SELECT RAISE(ABORT, 'forced'); END;",
            new.id.to_hex()
        ))
        .unwrap();

    assert!(block_on(store.put(validated(new, &account))).is_err());

    let public = authorized(&account, Filter::new().kind(Kind::Metadata));
    assert_eq!(query(&store, &[public], NOW), vec![old]);
}

#[test]
fn expired_events_are_hidden_on_read_and_compaction_deletes_them() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let disposable = keys(0x22);
    let expiring = inbox(&disposable, &account, 1);
    assert_eq!(
        put(&store, expiring.clone(), &account),
        StoreOutcome::Stored
    );
    let inbox_query = authorized(
        &account,
        Filter::new().kind(Kind::GiftWrap).custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            account.public_key().to_hex(),
        ),
    );

    assert_eq!(
        query(&store, std::slice::from_ref(&inbox_query), NOW),
        vec![expiring]
    );
    assert!(query(&store, std::slice::from_ref(&inbox_query), NOW + 7 * DAY).is_empty());
    assert_eq!(block_on(store.compact(NOW + 7 * DAY)).unwrap(), 1);
    assert_eq!(block_on(store.compact(NOW + 7 * DAY)).unwrap(), 0);
    assert!(query(&store, &[inbox_query], NOW).is_empty());
}

#[test]
fn corrupt_rows_fail_the_query_instead_of_starving_a_limited_result() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    let account = keys(0x11);
    let event = metadata(&account, NOW, "valid");
    assert_eq!(put(&store, event.clone(), &account), StoreOutcome::Stored);
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE events SET event_json = '{}' WHERE id = ?1",
            [event.id.to_hex()],
        )
        .unwrap();

    let public = authorized(&account, Filter::new().kind(Kind::Metadata));
    assert!(matches!(
        block_on(store.query(&[public], NOW, 1)),
        Err(Error::CorruptRow)
    ));
}

#[test]
fn opening_creates_a_private_state_directory_and_rejects_bad_schema_versions() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("private-state");
    let path = state_dir.join("relay.sqlite3");
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    drop(store);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    let newer = temp.path().join("newer").join("relay.sqlite3");
    let newer_store = block_on(SqliteStore::open(&newer, 8)).unwrap();
    block_on(newer_store.shutdown()).unwrap();
    let connection = Connection::open(&newer).unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);
    assert!(matches!(
        block_on(SqliteStore::open(&newer, 8)),
        Err(Error::UnsupportedSchema {
            actual: 2,
            supported: 1
        })
    ));

    let malformed = temp.path().join("malformed").join("relay.sqlite3");
    let malformed_store = block_on(SqliteStore::open(&malformed, 8)).unwrap();
    block_on(malformed_store.shutdown()).unwrap();
    Connection::open(&malformed)
        .unwrap()
        .execute_batch(
            "DROP TABLE events; CREATE TABLE events (wrong INTEGER); PRAGMA user_version = 1;",
        )
        .unwrap();
    assert!(matches!(
        block_on(SqliteStore::open(&malformed, 8)),
        Err(Error::MalformedSchema)
    ));
}

#[test]
fn opening_a_bare_relative_database_path_is_rejected() {
    assert!(matches!(
        block_on(SqliteStore::open("relay.sqlite3", 8)),
        Err(Error::MissingStateDirectory)
    ));
}

#[test]
fn startup_waits_asynchronously_while_sqlite_is_busy() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    block_on(store.shutdown()).unwrap();
    let external = Connection::open(&path).unwrap();
    external.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let mut opening = SqliteStore::open(&path, 8);
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(matches!(opening.as_mut().poll(&mut context), Poll::Pending));

    external.execute_batch("ROLLBACK").unwrap();
    let reopened = block_on(opening).unwrap();
    block_on(reopened.shutdown()).unwrap();
}

#[test]
fn declared_schema_version_rejects_an_index_with_the_right_name_but_wrong_definition() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    block_on(store.shutdown()).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP INDEX events_replacement;
             CREATE INDEX events_replacement ON events(replacement_key);",
        )
        .unwrap();

    assert!(matches!(
        block_on(SqliteStore::open(&path, 8)),
        Err(Error::MalformedSchema)
    ));
}

#[test]
fn declared_schema_version_rejects_unexpected_triggers() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    block_on(store.shutdown()).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER unexpected_delete AFTER INSERT ON events
             BEGIN DELETE FROM events WHERE id = NEW.id; END;",
        )
        .unwrap();

    assert!(matches!(
        block_on(SqliteStore::open(&path, 8)),
        Err(Error::MalformedSchema)
    ));
}

#[test]
fn parent_directory_components_are_rejected_before_filesystem_changes() {
    let temp = TempDir::new().unwrap();
    let traversing = temp
        .path()
        .join("should-not-be-created")
        .join("..")
        .join("relay.sqlite3");

    assert!(matches!(
        block_on(SqliteStore::open(&traversing, 8)),
        Err(Error::UnsafeStatePath)
    ));
    assert!(!temp.path().join("should-not-be-created").exists());
    assert!(!temp.path().join("relay.sqlite3").exists());
}

#[test]
fn unpolled_put_future_never_enters_the_command_queue() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let event = metadata(&account, NOW, "unpolled");

    drop(store.put(validated(event.clone(), &account)));

    assert_eq!(put(&store, event.clone(), &account), StoreOutcome::Stored);
}

#[test]
fn accepted_put_completes_after_its_reply_future_is_dropped() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 8)).unwrap();
    let account = keys(0x11);
    let event = metadata(&account, NOW, "accepted");
    let external = Connection::open(&path).unwrap();
    external.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let mut accepted = store.put(validated(event.clone(), &account));
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(matches!(
        accepted.as_mut().poll(&mut context),
        Poll::Pending
    ));
    drop(accepted);
    external.execute_batch("ROLLBACK").unwrap();

    assert_eq!(
        put(&store, event.clone(), &account),
        StoreOutcome::Duplicate
    );
    let public = authorized(&account, Filter::new().kind(Kind::Metadata));
    assert_eq!(query(&store, &[public], NOW), vec![event]);
}

#[test]
fn dropped_query_reply_does_not_stop_the_worker() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let event = metadata(&account, NOW, "still-running");
    assert_eq!(put(&store, event.clone(), &account), StoreOutcome::Stored);
    let public = authorized(&account, Filter::new().kind(Kind::Metadata));

    drop(store.query(std::slice::from_ref(&public), NOW, 10));

    assert_eq!(query(&store, &[public], NOW), vec![event]);
}

#[test]
fn bounded_queue_cancellation_before_capacity_never_executes() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 1)).unwrap();
    let account = keys(0x11);
    let external = Connection::open(&path).unwrap();
    external.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let mut first = store.put(validated(key_package(&account, NOW, "one", 1), &account));
    let mut second = store.put(validated(key_package(&account, NOW, "two", 2), &account));
    let rejected = key_package(&account, NOW, "three", 3);
    let mut before_capacity = store.put(validated(rejected.clone(), &account));
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
    assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));
    assert!(matches!(
        before_capacity.as_mut().poll(&mut context),
        Poll::Pending
    ));
    drop(before_capacity);

    external.execute_batch("ROLLBACK").unwrap();
    assert_eq!(block_on(first).unwrap(), StoreOutcome::Stored);
    assert_eq!(block_on(second).unwrap(), StoreOutcome::Stored);
    let public = authorized(&account, Filter::new().kind(Kind::Custom(30_443)));
    assert!(!ids(&query(&store, &[public], NOW)).contains(&rejected.id.to_hex()));
}

#[test]
fn zero_result_queries_do_no_work_and_explicit_shutdown_is_stable() {
    let temp = TempDir::new().unwrap();
    let store = open(&temp);
    let account = keys(0x11);
    let public = authorized(&account, Filter::new().kind(Kind::Metadata));
    assert!(
        block_on(store.query(&[public], u64::MAX, 0))
            .unwrap()
            .is_empty()
    );

    block_on(store.clone().shutdown()).unwrap();
    let event = validated(metadata(&account, NOW, "after-shutdown"), &account);
    assert!(matches!(
        block_on(store.put(event.clone())),
        Err(Error::WorkerStopped)
    ));
    assert!(matches!(
        block_on(store.put(event)),
        Err(Error::WorkerStopped)
    ));
}

#[test]
fn shutdown_drains_commands_admitted_ahead_of_it_and_rejects_later_work() {
    let temp = TempDir::new().unwrap();
    let path = db_path(&temp);
    let store = block_on(SqliteStore::open(&path, 1)).unwrap();
    let account = keys(0x11);
    let first_event = key_package(&account, NOW, "first", 1);
    let second_event = key_package(&account, NOW, "second", 2);
    let late_event = key_package(&account, NOW, "late", 3);
    let external = Connection::open(&path).unwrap();
    external.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let mut first = store.put(validated(first_event.clone(), &account));
    let mut second = store.put(validated(second_event.clone(), &account));
    let mut shutdown = store.clone().shutdown();
    let mut late = store.put(validated(late_event.clone(), &account));
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
    assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));
    assert!(matches!(
        shutdown.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert!(matches!(late.as_mut().poll(&mut context), Poll::Pending));

    external.execute_batch("ROLLBACK").unwrap();
    assert_eq!(block_on(first).unwrap(), StoreOutcome::Stored);
    assert_eq!(block_on(second).unwrap(), StoreOutcome::Stored);
    block_on(shutdown).unwrap();
    assert!(matches!(block_on(late), Err(Error::WorkerStopped)));

    let reopened = block_on(SqliteStore::open(&path, 8)).unwrap();
    let packages = authorized(&account, Filter::new().kind(Kind::Custom(30_443)));
    let stored = ids(&query(&reopened, &[packages], NOW));
    assert!(stored.contains(&first_event.id.to_hex()));
    assert!(stored.contains(&second_event.id.to_hex()));
    assert!(!stored.contains(&late_event.id.to_hex()));
}

#[allow(dead_code)]
fn store_api_accepts_only_authorized_queries<'a>(
    store: &'a SqliteStore,
    queries: &'a [AuthorizedQuery],
) -> deaddrop_relay_core::StoreFuture<'a, Result<Vec<Event>, deaddrop_relay_sqlite::Error>> {
    store.query(queries, NOW, 10)
}

use rusqlite::{Connection, OptionalExtension as _};

use crate::Error;

const SCHEMA_VERSION: i64 = 1;

pub(crate) fn migrate(connection: &Connection) -> Result<(), Error> {
    let version = connection
        .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
        .map_err(Error::database)?;
    match version {
        0 => {
            connection
                .execute_batch(include_str!("../migrations/0001_events.sql"))
                .map_err(Error::database)?;
            validate_schema(connection)
        }
        SCHEMA_VERSION => validate_schema(connection),
        actual => Err(Error::UnsupportedSchema {
            actual,
            supported: SCHEMA_VERSION,
        }),
    }
}

fn validate_schema(connection: &Connection) -> Result<(), Error> {
    const OBJECTS: &[(&str, &str, &str)] = &[
        (
            "table",
            "events",
            "CREATE TABLE events (\n    id              TEXT PRIMARY KEY NOT NULL,\n    event_json      TEXT NOT NULL,\n    kind            INTEGER NOT NULL,\n    pubkey          TEXT NOT NULL,\n    created_at      INTEGER NOT NULL,\n    received_at     INTEGER NOT NULL,\n    d_tag           TEXT,\n    p_tag           TEXT,\n    h_tag           TEXT,\n    expires_at      INTEGER,\n    replacement_key TEXT\n) STRICT",
        ),
        (
            "index",
            "events_public",
            "CREATE INDEX events_public\n    ON events(kind, created_at DESC, id ASC)\n    WHERE kind IN (0, 30443)",
        ),
        (
            "index",
            "events_inbox",
            "CREATE INDEX events_inbox\n    ON events(p_tag, kind, created_at DESC, id ASC)\n    WHERE p_tag IS NOT NULL",
        ),
        (
            "index",
            "events_group",
            "CREATE INDEX events_group\n    ON events(h_tag, kind, created_at DESC, id ASC)\n    WHERE h_tag IS NOT NULL",
        ),
        (
            "index",
            "events_replacement",
            "CREATE UNIQUE INDEX events_replacement\n    ON events(replacement_key)\n    WHERE replacement_key IS NOT NULL",
        ),
        (
            "index",
            "events_expiry",
            "CREATE INDEX events_expiry\n    ON events(expires_at)\n    WHERE expires_at IS NOT NULL",
        ),
    ];
    let object_count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(Error::database)?;
    if usize::try_from(object_count).ok() != Some(OBJECTS.len()) {
        return Err(Error::MalformedSchema);
    }
    for (object_type, name, expected_sql) in OBJECTS {
        let actual = connection
            .query_row(
                "SELECT type, tbl_name, sql FROM sqlite_schema WHERE name = ?1",
                [name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(Error::database)?;
        if actual.as_ref().is_none_or(|(actual_type, table, sql)| {
            actual_type != object_type || table != "events" || sql != expected_sql
        }) {
            return Err(Error::MalformedSchema);
        }
    }
    Ok(())
}

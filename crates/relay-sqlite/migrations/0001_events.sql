BEGIN IMMEDIATE;

CREATE TABLE events (
    id              TEXT PRIMARY KEY NOT NULL,
    event_json      TEXT NOT NULL,
    kind            INTEGER NOT NULL,
    pubkey          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    received_at     INTEGER NOT NULL,
    d_tag           TEXT,
    p_tag           TEXT,
    h_tag           TEXT,
    expires_at      INTEGER,
    replacement_key TEXT
) STRICT;

CREATE INDEX events_public
    ON events(kind, created_at DESC, id ASC)
    WHERE kind IN (0, 30443);
CREATE INDEX events_inbox
    ON events(p_tag, kind, created_at DESC, id ASC)
    WHERE p_tag IS NOT NULL;
CREATE INDEX events_group
    ON events(h_tag, kind, created_at DESC, id ASC)
    WHERE h_tag IS NOT NULL;
CREATE UNIQUE INDEX events_replacement
    ON events(replacement_key)
    WHERE replacement_key IS NOT NULL;
CREATE INDEX events_expiry
    ON events(expires_at)
    WHERE expires_at IS NOT NULL;

PRAGMA user_version = 1;
COMMIT;

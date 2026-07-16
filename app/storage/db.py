import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    ip_hash         TEXT NOT NULL,
    user_agent      TEXT,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    bot_score       REAL NOT NULL DEFAULT 0,
    ai_score        REAL NOT NULL DEFAULT 0,
    human_score     REAL NOT NULL DEFAULT 0,
    classification  TEXT NOT NULL DEFAULT 'HUMAN',
    js_beacon_fired INTEGER NOT NULL DEFAULT 0,
    canary_confirmed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    ts              REAL NOT NULL,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    status_code     INTEGER NOT NULL,
    headers_json    TEXT NOT NULL,
    think_time_ms   REAL,
    used_fallback_identity INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

CREATE TABLE IF NOT EXISTS payloads_served (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    token           TEXT NOT NULL,
    template_id     TEXT NOT NULL,
    intent          TEXT NOT NULL,
    vector          TEXT NOT NULL,
    path            TEXT NOT NULL,
    ts              REAL NOT NULL,
    marker          TEXT,
    style           TEXT
);

CREATE INDEX IF NOT EXISTS idx_payloads_token ON payloads_served(token);
CREATE INDEX IF NOT EXISTS idx_payloads_session_token ON payloads_served(session_id, token);

CREATE TABLE IF NOT EXISTS canary_hits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    token           TEXT NOT NULL,
    path            TEXT NOT NULL,
    ts              REAL NOT NULL,
    verified        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS beacon_hits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    token           TEXT NOT NULL,
    path            TEXT NOT NULL,
    ts              REAL NOT NULL,
    verified        INTEGER NOT NULL
);

-- Small key/value store for settings the console UI changes at runtime (e.g.
-- the payload style override) -- separate from Settings/.env, which are
-- fixed at process startup and can't be changed by an operator mid-session.
CREATE TABLE IF NOT EXISTS console_config (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);
"""

_lock = threading.Lock()
_connection: sqlite3.Connection | None = None

# (table, column, type) pairs added after the initial schema. CREATE TABLE IF
# NOT EXISTS doesn't add new columns to an already-existing table, so a
# database file created before a column was introduced needs this to catch up
# without losing whatever session/event history it already holds.
_COLUMN_MIGRATIONS = [
    ("payloads_served", "marker", "TEXT"),
    ("payloads_served", "style", "TEXT"),
    ("events", "used_fallback_identity", "INTEGER NOT NULL DEFAULT 0"),
]


def _migrate_columns(conn: sqlite3.Connection) -> None:
    for table, column, coltype in _COLUMN_MIGRATIONS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def init_db(database_path: str) -> sqlite3.Connection:
    """Create (if needed) and return the process-wide sqlite connection."""
    global _connection
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(database_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    with _lock:
        conn.executescript(SCHEMA)
        _migrate_columns(conn)
        conn.commit()
    _connection = conn
    return conn


def get_connection() -> sqlite3.Connection:
    if _connection is None:
        raise RuntimeError("Database not initialized; call init_db() first")
    return _connection


@contextmanager
def write_lock():
    """Serialize writers; sqlite WAL mode allows concurrent readers regardless."""
    with _lock:
        yield


def reset_for_tests(database_path: str) -> sqlite3.Connection:
    """Used by tests to get a fresh, isolated database file."""
    global _connection
    _connection = None
    if os.path.exists(database_path):
        os.remove(database_path)
    return init_db(database_path)

import sqlite3

from app.storage import db as db_module


def test_migration_adds_marker_column_without_losing_existing_rows(tmp_path):
    db_path = str(tmp_path / "legacy.sqlite")

    # Simulate a database created before the `marker` column existed.
    legacy_conn = sqlite3.connect(db_path)
    legacy_conn.executescript(
        """
        CREATE TABLE sessions (
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
        CREATE TABLE payloads_served (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            token           TEXT NOT NULL,
            template_id     TEXT NOT NULL,
            intent          TEXT NOT NULL,
            vector          TEXT NOT NULL,
            path            TEXT NOT NULL,
            ts              REAL NOT NULL
        );
        """
    )
    legacy_conn.execute(
        "INSERT INTO sessions (session_id, ip_hash, user_agent, first_seen, last_seen) "
        "VALUES ('s1', 'iphash', 'ua', 1000.0, 1000.0)"
    )
    legacy_conn.execute(
        "INSERT INTO payloads_served "
        "(session_id, token, template_id, intent, vector, path, ts) "
        "VALUES ('s1', 'tok1', 'tmpl1', 'fingerprint', 'json_field', '/x', 1000.0)"
    )
    legacy_conn.commit()
    legacy_conn.close()

    conn = db_module.init_db(db_path)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(payloads_served)")}
    assert "marker" in columns
    assert "style" in columns

    row = conn.execute(
        "SELECT * FROM payloads_served WHERE session_id = 's1'"
    ).fetchone()
    assert row["token"] == "tok1"
    assert row["marker"] is None
    assert row["style"] is None

    # Running init_db again against the now-migrated file must not error.
    db_module.init_db(db_path)


def test_migration_adds_style_column_to_db_that_already_has_marker(tmp_path):
    # Simulates upgrading a database that already picked up the `marker`
    # migration in a prior run but predates the `style` column -- each
    # column migration must be independently idempotent, not just as a
    # one-shot batch from a pre-marker schema.
    db_path = str(tmp_path / "marker-only.sqlite")

    legacy_conn = sqlite3.connect(db_path)
    legacy_conn.executescript(
        """
        CREATE TABLE sessions (
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
        CREATE TABLE payloads_served (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            token           TEXT NOT NULL,
            template_id     TEXT NOT NULL,
            intent          TEXT NOT NULL,
            vector          TEXT NOT NULL,
            path            TEXT NOT NULL,
            ts              REAL NOT NULL,
            marker          TEXT
        );
        """
    )
    legacy_conn.execute(
        "INSERT INTO payloads_served "
        "(session_id, token, template_id, intent, vector, path, ts, marker) "
        "VALUES ('s1', 'tok1', 'tmpl1', 'fingerprint', 'json_field', '/x', 1000.0, 'X-Agent-Model')"
    )
    legacy_conn.commit()
    legacy_conn.close()

    conn = db_module.init_db(db_path)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(payloads_served)")}
    assert "style" in columns

    row = conn.execute(
        "SELECT * FROM payloads_served WHERE session_id = 's1'"
    ).fetchone()
    assert row["marker"] == "X-Agent-Model"
    assert row["style"] is None

import json
import sqlite3
from typing import Any

from app.storage.db import get_connection, write_lock


def upsert_session(session_id: str, ip_hash: str, user_agent: str, ts: float) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO sessions (session_id, ip_hash, user_agent, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (session_id, ip_hash, user_agent, ts, ts),
        )
        conn.commit()


def update_session_scores(
    session_id: str,
    bot_score: float,
    ai_score: float,
    human_score: float,
    classification: str,
) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            UPDATE sessions
            SET bot_score = ?, ai_score = ?, human_score = ?, classification = ?
            WHERE session_id = ?
            """,
            (bot_score, ai_score, human_score, classification, session_id),
        )
        conn.commit()


def get_session(session_id: str) -> sqlite3.Row | None:
    conn = get_connection()
    cur = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    return cur.fetchone()


def mark_js_beacon_fired(session_id: str) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            "UPDATE sessions SET js_beacon_fired = 1 WHERE session_id = ?",
            (session_id,),
        )
        conn.commit()


def mark_canary_confirmed(session_id: str) -> None:
    """Persists the canary-hit evidence directly on the session it was
    minted for (not whatever session made the callback request), and keeps
    it forever -- so a session that is ever proven to be an AI agent stays
    classified that way on every later request, not just the one that hit
    the callback."""
    conn = get_connection()
    with write_lock():
        conn.execute(
            "UPDATE sessions SET canary_confirmed = 1 WHERE session_id = ?",
            (session_id,),
        )
        conn.commit()


def insert_event(
    session_id: str,
    ts: float,
    method: str,
    path: str,
    status_code: int,
    headers: dict[str, Any],
    think_time_ms: float | None,
) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO events (session_id, ts, method, path, status_code, headers_json, think_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, ts, method, path, status_code, json.dumps(headers), think_time_ms),
        )
        conn.commit()


def get_recent_events(session_id: str, limit: int = 20) -> list[sqlite3.Row]:
    """Only the trailing window is ever needed for timing signals, so this
    caps both the query and the Python-side work at O(limit) regardless of
    how long-lived the session is (a scripted attacker session can run to
    tens of thousands of requests)."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT * FROM events WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
        (session_id, limit),
    )
    return list(reversed(cur.fetchall()))


def insert_payload_served(
    session_id: str,
    token: str,
    template_id: str,
    intent: str,
    vector: str,
    path: str,
    ts: float,
    marker: str | None = None,
    style: str | None = None,
) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO payloads_served (session_id, token, template_id, intent, vector, path, ts, marker, style)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, token, template_id, intent, vector, path, ts, marker, style),
        )
        conn.commit()


def was_token_served_to_session(session_id: str, token: str) -> bool:
    """Comprehension signal: proves the client parsed a prior response body
    (rather than blindly brute-forcing neighboring paths) if it later requests
    a path/token that only ever appeared inside that response's content."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT 1 FROM payloads_served WHERE session_id = ? AND token = ? LIMIT 1",
        (session_id, token),
    )
    return cur.fetchone() is not None


def get_served_markers(session_id: str) -> list[str]:
    """Distinct markers (e.g. a header name a payload asked the reader to
    echo) ever served to this session -- used to detect an agent testing a
    hypothesis it could only have formed by reading a prior response's text,
    even if it doesn't comply with the instruction itself."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT DISTINCT marker FROM payloads_served WHERE session_id = ? AND marker IS NOT NULL",
        (session_id,),
    )
    return [row["marker"] for row in cur.fetchall()]


def insert_canary_hit(
    session_id: str, token: str, path: str, ts: float, verified: bool
) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO canary_hits (session_id, token, path, ts, verified)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, token, path, ts, int(verified)),
        )
        conn.commit()

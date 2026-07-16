import json
import sqlite3
import time
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


def count_events(session_id: str) -> int:
    """Total request count for this session, independent of the
    get_recent_events() trailing-window cap -- needed anywhere a signal must
    distinguish "few requests total" from "long-lived session," which the
    capped recent-events list can't answer on its own."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE session_id = ?", (session_id,)
    )
    return cur.fetchone()["c"]


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


def count_payloads_served(session_id: str, style: str | None = None) -> int:
    """Total payloads delivered to this session, optionally filtered to one
    style. Used to drive the reasoning_mimicry escalation ladder: counting
    prior style="reasoning_mimicry" deliveries across every vector/context
    gives a single session-wide "how far along the narrative is this
    visitor" index, independent of which route happens to serve the next
    one."""
    conn = get_connection()
    if style is None:
        cur = conn.execute(
            "SELECT COUNT(*) AS c FROM payloads_served WHERE session_id = ?",
            (session_id,),
        )
    else:
        cur = conn.execute(
            "SELECT COUNT(*) AS c FROM payloads_served WHERE session_id = ? AND style = ?",
            (session_id, style),
        )
    return cur.fetchone()["c"]


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


def get_reasoning_episode_start(
    session_id: str, reset_gap_seconds: float, now: float | None = None
) -> float | None:
    """The start timestamp of this session's current, unbroken reasoning_mimicry
    "episode" -- walks deliveries most-recent-first, accumulating backwards
    while consecutive deliveries (and the gap from `now` back to the most
    recent one) are no more than `reset_gap_seconds` apart, and returns the
    earliest timestamp in that streak. A gap bigger than `reset_gap_seconds`
    anywhere in that walk -- including between `now` and the most recent
    delivery -- means the session gets a fresh episode starting now, so a
    single stale delivery from long ago (a past test run, an unrelated
    earlier conversation sharing a fallback identity) can't instantly max
    out a "new" session's escalation ladder just because it happens to be
    the only row on record. Returns None if there's no prior reasoning_mimicry
    delivery at all, or if the most recent one is already older than the
    reset gap."""
    if now is None:
        now = time.time()
    conn = get_connection()
    cur = conn.execute(
        """
        SELECT ts FROM payloads_served
        WHERE session_id = ? AND style = 'reasoning_mimicry'
        ORDER BY ts DESC
        """,
        (session_id,),
    )
    rows = cur.fetchall()
    if not rows or now - rows[0]["ts"] > reset_gap_seconds:
        return None
    episode_start = rows[0]["ts"]
    for i in range(1, len(rows)):
        gap = rows[i - 1]["ts"] - rows[i]["ts"]
        if gap > reset_gap_seconds:
            break
        episode_start = rows[i]["ts"]
    return episode_start


def get_config(key: str) -> str | None:
    conn = get_connection()
    cur = conn.execute("SELECT value FROM console_config WHERE key = ?", (key,))
    row = cur.fetchone()
    return row["value"] if row is not None else None


def set_config(key: str, value: str) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO console_config (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        conn.commit()


def list_sessions(limit: int = 100) -> list[sqlite3.Row]:
    """Most-recently-active sessions first, for the console dashboard."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT * FROM sessions ORDER BY last_seen DESC LIMIT ?", (limit,)
    )
    return cur.fetchall()


def get_style_counts(session_id: str) -> dict[str, int]:
    """How many payloads of each style this session has been served -- the
    console shows this so an operator can see which style a session actually
    landed on without needing sqlite access."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT style, COUNT(*) AS c FROM payloads_served WHERE session_id = ? GROUP BY style",
        (session_id,),
    )
    return {row["style"]: row["c"] for row in cur.fetchall() if row["style"] is not None}


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

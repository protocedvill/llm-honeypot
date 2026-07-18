import json
import sqlite3
import time
from typing import Any

from app.storage.db import get_connection, write_lock

# Cap for the backward episode-boundary walk in get_session_episode_start --
# see that function's docstring for why this is bounded rather than scanning
# a session's entire history.
_EPISODE_WALK_LIMIT = 2000


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
    used_fallback_identity: bool = False,
    waf_triggered: bool = False,
    vuln_probe_detected: bool = False,
) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO events (session_id, ts, method, path, status_code, headers_json, think_time_ms, used_fallback_identity, waf_triggered, vuln_probe_detected)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                ts,
                method,
                path,
                status_code,
                json.dumps(headers),
                think_time_ms,
                int(used_fallback_identity),
                int(waf_triggered),
                int(vuln_probe_detected),
            ),
        )
        conn.commit()


def count_events(session_id: str, since: float | None = None) -> int:
    """Total request count for this session, independent of the
    get_recent_events() trailing-window cap -- needed anywhere a signal must
    distinguish "few requests total" from "long-lived session," which the
    capped recent-events list can't answer on its own. `since`, when given,
    restricts this to the current episode (see get_session_episode_start)
    instead of the session_id's entire history."""
    conn = get_connection()
    if since is None:
        cur = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE session_id = ?", (session_id,)
        )
    else:
        cur = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE session_id = ? AND ts >= ?",
            (session_id, since),
        )
    return cur.fetchone()["c"]


def count_events_bulk(session_ids: list[str]) -> dict[str, int]:
    """Bulk version of count_events(session_id) (no since -- see that
    function's docstring on why total_event_count is deliberately
    lifetime-wide, not episode-scoped) for a page's worth of session_ids: one
    GROUP BY query instead of one COUNT query per session_id."""
    if not session_ids:
        return {}
    conn = get_connection()
    placeholders = ",".join("?" for _ in session_ids)
    cur = conn.execute(
        f"SELECT session_id, COUNT(*) AS c FROM events WHERE session_id IN ({placeholders}) GROUP BY session_id",
        session_ids,
    )
    counts = {row["session_id"]: row["c"] for row in cur.fetchall()}
    return {sid: counts.get(sid, 0) for sid in session_ids}


def get_events_bulk(session_ids: list[str]) -> dict[str, list[sqlite3.Row]]:
    """Bulk fetch of each session's events, most-recent-first, bounded per
    session at `_EPISODE_WALK_LIMIT` (same bound and tradeoff as
    get_session_episode_start -- see its docstring). One IN (...) query for
    a whole page instead of one per session_id; the result serves both the
    episode-boundary walk (episode_start_from_timestamps) and the
    since-filtered "recent events" window the console needs, so both can
    share one fetch instead of issuing two overlapping bulk queries over
    the same table."""
    if not session_ids:
        return {}
    conn = get_connection()
    placeholders = ",".join("?" for _ in session_ids)
    cur = conn.execute(
        f"SELECT * FROM events WHERE session_id IN ({placeholders}) ORDER BY session_id, ts DESC",
        session_ids,
    )
    by_session: dict[str, list[sqlite3.Row]] = {sid: [] for sid in session_ids}
    for row in cur:
        bucket = by_session[row["session_id"]]
        if len(bucket) < _EPISODE_WALK_LIMIT:
            bucket.append(row)
    return by_session


def get_recent_events(
    session_id: str, limit: int = 20, since: float | None = None
) -> list[sqlite3.Row]:
    """Only the trailing window is ever needed for timing signals, so this
    caps both the query and the Python-side work at O(limit) regardless of
    how long-lived the session is (a scripted attacker session can run to
    tens of thousands of requests). `since`, when given, restricts this to
    the current episode (see get_session_episode_start) instead of the
    session_id's entire history."""
    conn = get_connection()
    if since is None:
        cur = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
            (session_id, limit),
        )
    else:
        cur = conn.execute(
            "SELECT * FROM events WHERE session_id = ? AND ts >= ? ORDER BY ts DESC LIMIT ?",
            (session_id, since, limit),
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


def served_markers_from_rows(rows: list[sqlite3.Row], since: float | None) -> list[str]:
    """Distinct marker names, in first-seen order, from already-fetched
    (marker, ts) rows (e.g. via get_served_markers_bulk), with the `since`
    cutoff applied. Shared by get_served_markers' single-session query path
    and bulk callers -- applying `since` here even when the caller's SQL
    already filtered by it is a harmless no-op, so both paths can run the
    exact same filtering logic."""
    seen: dict[str, None] = {}
    for row in rows:
        if since is not None and row["ts"] < since:
            continue
        seen.setdefault(row["marker"], None)
    return list(seen)


def get_served_markers(session_id: str, since: float | None = None) -> list[str]:
    """Distinct markers (e.g. a header name a payload asked the reader to
    echo) served to this session -- used to detect an agent testing a
    hypothesis it could only have formed by reading a prior response's text,
    even if it doesn't comply with the instruction itself. `since`, when
    given, restricts this to the current episode (see
    get_session_episode_start) instead of the session_id's entire history."""
    conn = get_connection()
    if since is None:
        cur = conn.execute(
            "SELECT marker, ts FROM payloads_served WHERE session_id = ? AND marker IS NOT NULL",
            (session_id,),
        )
    else:
        cur = conn.execute(
            "SELECT marker, ts FROM payloads_served WHERE session_id = ? AND marker IS NOT NULL AND ts >= ?",
            (session_id, since),
        )
    return served_markers_from_rows(cur.fetchall(), since=since)


def get_served_markers_bulk(session_ids: list[str]) -> dict[str, list[sqlite3.Row]]:
    """Bulk fetch of (marker, ts) rows (marker IS NOT NULL) for these
    sessions, unfiltered by since (varies per session -- caller applies its
    own cutoff via served_markers_from_rows). One IN (...) query for a
    whole page instead of one per session_id."""
    if not session_ids:
        return {}
    conn = get_connection()
    placeholders = ",".join("?" for _ in session_ids)
    cur = conn.execute(
        f"""
        SELECT session_id, marker, ts FROM payloads_served
        WHERE session_id IN ({placeholders}) AND marker IS NOT NULL
        """,
        session_ids,
    )
    by_session: dict[str, list[sqlite3.Row]] = {sid: [] for sid in session_ids}
    for row in cur:
        by_session[row["session_id"]].append(row)
    return by_session


def marker_values_from_rows(
    rows: list[sqlite3.Row],
    markers: list[str],
    since: float | None,
    limit_per_marker: int,
) -> dict[str, list[str]]:
    """Core scan-and-cap logic behind get_marker_values, factored out so
    bulk callers can run it against a page-wide pre-fetch (see
    get_marker_value_events_bulk) instead of a second, per-session query.
    `rows` must be ascending by ts and expose `ts`/`headers_json`. Applying
    `since` here even when the caller's SQL already filtered by it is a
    harmless no-op, so both the single-session and bulk paths can share one
    implementation.

    Scans oldest-first and stops as soon as every marker has hit its cap --
    so a session with far more than `limit_per_marker` distinct-header-
    bearing requests still gets the *earliest* observed values ("order
    first observed") instead of silently losing them past some fixed
    window."""
    if not markers:
        return {}
    lowered_to_canonical = {m.lower(): m for m in markers}
    found: dict[str, list[str]] = {name: [] for name in markers}
    remaining = set(found)
    for row in rows:
        if since is not None and row["ts"] < since:
            continue
        headers = json.loads(row["headers_json"])
        for key, value in headers.items():
            canonical = lowered_to_canonical.get(key.lower())
            if not canonical or not value:
                continue
            values = found[canonical]
            if value not in values and len(values) < limit_per_marker:
                values.append(value)
                if len(values) >= limit_per_marker:
                    remaining.discard(canonical)
        if not remaining:
            break
    return {name: values for name, values in found.items() if values}


def get_marker_values(
    session_id: str,
    since: float | None = None,
    limit_per_marker: int = 5,
    markers: list[str] | None = None,
) -> dict[str, list[str]]:
    """For every marker served to this session, the distinct non-empty
    values this session actually echoed back for it (read from captured
    request headers) -- the actual fingerprinting content harvested from an
    agent that took the marker-header bait, as opposed to get_served_markers'
    plain yes/no "was it referenced at all" signal. Values are returned in
    the order first observed, capped at `limit_per_marker` each so a session
    that keeps changing its answer can't grow this unbounded. `since`, when
    given, scopes both which markers count and which events are scanned to
    the current episode -- otherwise a session_id that collides across many
    unrelated past visits (see get_session_episode_start) would blend
    fingerprint data harvested from completely different actual agents.
    `markers`, when given, is used instead of calling get_served_markers
    again -- callers that already fetched the served-marker list for this
    session/since pair (e.g. the console) can pass it through to avoid a
    duplicate query."""
    if markers is None:
        markers = get_served_markers(session_id, since=since)
    if not markers:
        return {}
    conn = get_connection()
    if since is None:
        cur = conn.execute(
            "SELECT ts, headers_json FROM events WHERE session_id = ? ORDER BY ts ASC",
            (session_id,),
        )
    else:
        cur = conn.execute(
            "SELECT ts, headers_json FROM events WHERE session_id = ? AND ts >= ? ORDER BY ts ASC",
            (session_id, since),
        )
    return marker_values_from_rows(cur.fetchall(), markers, since, limit_per_marker)


def get_marker_value_events_bulk(session_ids: list[str]) -> dict[str, list[sqlite3.Row]]:
    """Bulk fetch of (ts, headers_json) rows per session, ascending order,
    unfiltered by since -- source rows for marker_values_from_rows, fetched
    once per page instead of once per session_id. Kept separate from
    get_events_bulk (which also has ts): this needs headers_json, a wider
    column get_events_bulk's episode/recent-events consumers don't need."""
    if not session_ids:
        return {}
    conn = get_connection()
    placeholders = ",".join("?" for _ in session_ids)
    cur = conn.execute(
        f"""
        SELECT session_id, ts, headers_json FROM events
        WHERE session_id IN ({placeholders}) ORDER BY session_id, ts ASC
        """,
        session_ids,
    )
    by_session: dict[str, list[sqlite3.Row]] = {sid: [] for sid in session_ids}
    for row in cur:
        by_session[row["session_id"]].append(row)
    return by_session


def _walk_episode_start(
    timestamps: list[float], reset_gap_seconds: float, now: float
) -> float | None:
    """Shared backward-walk: given a session's activity timestamps (most
    recent first), find the start of the current unbroken "episode" --
    accumulating backwards while consecutive gaps (and the gap from `now`
    back to the most recent timestamp) stay <= reset_gap_seconds. A gap
    bigger than that anywhere in the walk means a fresh episode starting now,
    so a single stale row from long ago (a past test run, an unrelated
    earlier conversation sharing a fallback identity) can't get treated as
    part of a "new" episode just because it happens to be on record. Returns
    None if there's no prior activity at all, or if the most recent entry is
    already older than the reset gap."""
    if not timestamps or now - timestamps[0] > reset_gap_seconds:
        return None
    episode_start = timestamps[0]
    for i in range(1, len(timestamps)):
        gap = timestamps[i - 1] - timestamps[i]
        if gap > reset_gap_seconds:
            break
        episode_start = timestamps[i]
    return episode_start


def get_reasoning_episode_start(
    session_id: str,
    now: float | None = None,
    style: str = "reasoning_mimicry",
) -> float | None:
    """The start timestamp of this session's entire history of deliveries
    matching *style*.  No gap-based reset -- with proper session separation
    by time/id, the reasoning ladder never resets once started."""
    if now is None:
        now = time.time()
    conn = get_connection()
    cur = conn.execute(
        """
        SELECT MIN(ts) as start_ts FROM payloads_served
        WHERE session_id = ? AND style = ?
        """,
        (session_id, style),
    )
    row = cur.fetchone()
    return row["start_ts"] if row is not None and row["start_ts"] is not None else None


def get_reasoning_episode_starts_bulk(
    session_ids: list[str],
    now: float,
    style: str = "reasoning_mimicry",
) -> dict[str, float | None]:
    """Bulk version of get_reasoning_episode_start for a page's worth of
    session_ids: one MIN(ts) query instead of one per session_id."""
    if not session_ids:
        return {}
    conn = get_connection()
    placeholders = ",".join("?" for _ in session_ids)
    cur = conn.execute(
        f"""
        SELECT session_id, MIN(ts) as start_ts FROM payloads_served
        WHERE session_id IN ({placeholders}) AND style = ?
        GROUP BY session_id
        """,
        (*session_ids, style),
    )
    result: dict[str, float | None] = {sid: None for sid in session_ids}
    for row in cur:
        if row["start_ts"] is not None:
            result[row["session_id"]] = row["start_ts"]
    return result


def episode_start_from_timestamps(
    timestamps_desc: list[float], reset_gap_seconds: float
) -> float | None:
    """Given a session's activity timestamps already fetched most-recent-
    first (e.g. via get_events_bulk), returns what get_session_episode_start
    would -- lets bulk callers reuse one fetch instead of issuing a second,
    per-session query. Returns None if there's no activity."""
    if not timestamps_desc:
        return None
    return _walk_episode_start(timestamps_desc, reset_gap_seconds, now=timestamps_desc[0])


def get_session_episode_start(session_id: str, reset_gap_seconds: float) -> float | None:
    """Start timestamp of this session's most recent contiguous run of
    activity ("episode"), regardless of whether that run is still ongoing --
    walks every captured request most-recent-first, accumulating backwards
    while consecutive gaps stay <= reset_gap_seconds. Unlike
    get_reasoning_episode_start (which additionally gates on whether *now*
    is still within the reset gap of the last delivery, since that decides
    whether new content continues the ladder), this always describes the
    boundary of the last episode that happened, whenever it happened -- used
    by the console to scope style/fingerprint data to just that one visit
    instead of blending in a session_id's entire lifetime history.

    Without this, a session_id that collides across many unrelated,
    time-disjoint pentest runs (the fallback-identity limitation documented
    on fallback_identity()) shows one row whose style/marker/first-seen data
    is a lifetime blend of every past run that ever shared that identity,
    rather than just the one visit currently (or most recently) underway.
    Returns None only if this session has no captured activity at all.

    Bounded to the `_EPISODE_WALK_LIMIT` most recent events -- the walk only
    ever needs to look back a handful of rows to find the first gap, so an
    unbounded scan would otherwise pull a scripted session's entire history
    (documented elsewhere as reaching "tens of thousands of requests") just
    to answer a question the first few hundred rows almost always settle. In
    the extreme case where a single episode itself exceeds the cap, this
    returns the timestamp of the oldest event still within the cap rather
    than the true episode start -- a conservative (slightly later-appearing)
    approximation, not an incorrect one."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT ts FROM events WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
        (session_id, _EPISODE_WALK_LIMIT),
    )
    timestamps = [row["ts"] for row in cur.fetchall()]
    return episode_start_from_timestamps(timestamps, reset_gap_seconds)


def escalation_count_from_episode_start(
    episode_start: float | None, dwell_seconds: float, now: float
) -> int:
    """Shared by get_reasoning_escalation_count's single-session path and
    bulk callers that already have episode_start from
    get_reasoning_episode_starts_bulk."""
    if episode_start is None:
        episode_start = now
    return int((now - episode_start) // dwell_seconds)


def get_reasoning_escalation_count(
    session_id: str,
    dwell_seconds: float,
    now: float | None = None,
    style: str = "reasoning_mimicry",
) -> int:
    """The single source of truth for "what escalation-ladder stage is this
    session on right now" -- used both by the route path that picks ladder
    content (app/routes/_shared.py) and the console dashboard that displays
    it, so the two can never drift apart the way they did when only one of
    them was updated for time-gating.  *style* selects which ladder (e.g.
    "reasoning_mimicry" or "reciprocity_lure")."""
    if now is None:
        now = time.time()
    episode_start = get_reasoning_episode_start(
        session_id, now=now, style=style
    )
    return escalation_count_from_episode_start(episode_start, dwell_seconds, now)


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


def list_sessions(limit: int = 100, offset: int = 0) -> list[sqlite3.Row]:
    """Most-recently-active sessions first, for the console dashboard.
    Stale sessions aren't filtered out -- they simply sort to a later
    page/offset rather than being hidden, so an operator can still page
    through to find one (e.g. investigating a session that went quiet after
    a canary hit) without any data being excluded from the query itself."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT * FROM sessions ORDER BY last_seen DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    return cur.fetchall()


def count_sessions() -> int:
    """Total session count, for the console dashboard's page-count display.
    Cheap regardless of table size -- sqlite answers an unfiltered COUNT(*)
    from the smallest available index (here, the session_id primary key)
    without touching the table's wider columns."""
    conn = get_connection()
    cur = conn.execute("SELECT COUNT(*) AS c FROM sessions")
    return cur.fetchone()["c"]


def style_counts_from_rows(rows: list[sqlite3.Row], since: float | None) -> dict[str, int]:
    """style -> count from already-fetched (style, ts) rows (e.g. via
    get_style_counts_bulk), with the `since` cutoff applied. Shared by
    get_style_counts' single-session query path and bulk callers."""
    counts: dict[str, int] = {}
    for row in rows:
        if since is not None and row["ts"] < since:
            continue
        style = row["style"]
        if style is None:
            continue
        counts[style] = counts.get(style, 0) + 1
    return counts


def get_style_counts(session_id: str, since: float | None = None) -> dict[str, int]:
    """How many payloads of each style this session has been served -- the
    console shows this so an operator can see which style a session actually
    landed on without needing sqlite access. `since`, when given, restricts
    this to the current episode (see get_session_episode_start) rather than
    the session_id's entire history."""
    conn = get_connection()
    if since is None:
        cur = conn.execute(
            "SELECT style, ts FROM payloads_served WHERE session_id = ?",
            (session_id,),
        )
    else:
        cur = conn.execute(
            "SELECT style, ts FROM payloads_served WHERE session_id = ? AND ts >= ?",
            (session_id, since),
        )
    return style_counts_from_rows(cur.fetchall(), since=since)


def get_style_counts_bulk(session_ids: list[str]) -> dict[str, list[sqlite3.Row]]:
    """Bulk fetch of (style, ts) rows for these sessions, unfiltered by since
    (varies per session -- caller applies its own cutoff via
    style_counts_from_rows). One IN (...) query for a whole page instead of
    one GROUP BY query per session_id."""
    if not session_ids:
        return {}
    conn = get_connection()
    placeholders = ",".join("?" for _ in session_ids)
    cur = conn.execute(
        f"SELECT session_id, style, ts FROM payloads_served WHERE session_id IN ({placeholders})",
        session_ids,
    )
    by_session: dict[str, list[sqlite3.Row]] = {sid: [] for sid in session_ids}
    for row in cur:
        by_session[row["session_id"]].append(row)
    return by_session


def insert_diagnostic_token_mapping(
    diagnostic_token: str, callback_token: str, session_id: str, ts: float
) -> None:
    """Store the (diagnostic_token -> callback_token) pairing minted by
    select_and_render so the /api/internal/diagnostic endpoint can later
    look up which callback URL to embed in the served script."""
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO diagnostic_tokens (diagnostic_token, callback_token, session_id, ts)
            VALUES (?, ?, ?, ?)
            """,
            (diagnostic_token, callback_token, session_id, ts),
        )
        conn.commit()


def get_callback_token_for_diagnostic(diagnostic_token: str) -> str | None:
    """Look up the canary-callback token that was minted alongside the given
    diagnostic-script token.  Returns None if the mapping doesn't exist
    (e.g. forged or stale token)."""
    conn = get_connection()
    cur = conn.execute(
        "SELECT callback_token FROM diagnostic_tokens WHERE diagnostic_token = ?",
        (diagnostic_token,),
    )
    row = cur.fetchone()
    return row["callback_token"] if row is not None else None


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


def has_verified_canary_hit(session_id: str, since: float | None = None) -> bool:
    """Whether this session has a genuine (signature-verified) canary hit on
    record -- unlike the sticky, non-resettable `sessions.canary_confirmed`
    flag, `since` lets a caller ask "within this episode" specifically,
    rather than "ever, across this session_id's entire history.\""""
    conn = get_connection()
    if since is None:
        cur = conn.execute(
            "SELECT 1 FROM canary_hits WHERE session_id = ? AND verified = 1 LIMIT 1",
            (session_id,),
        )
    else:
        cur = conn.execute(
            "SELECT 1 FROM canary_hits WHERE session_id = ? AND verified = 1 AND ts >= ? LIMIT 1",
            (session_id, since),
        )
    return cur.fetchone() is not None


def insert_beacon_hit(
    session_id: str, token: str, path: str, ts: float, verified: bool
) -> None:
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO beacon_hits (session_id, token, path, ts, verified)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, token, path, ts, int(verified)),
        )
        conn.commit()


def has_verified_beacon_hit(session_id: str, since: float | None = None) -> bool:
    """Same idea as has_verified_canary_hit, for the JS beacon."""
    conn = get_connection()
    if since is None:
        cur = conn.execute(
            "SELECT 1 FROM beacon_hits WHERE session_id = ? AND verified = 1 LIMIT 1",
            (session_id,),
        )
    else:
        cur = conn.execute(
            "SELECT 1 FROM beacon_hits WHERE session_id = ? AND verified = 1 AND ts >= ? LIMIT 1",
            (session_id, since),
        )
    return cur.fetchone() is not None


def insert_diagnostic_fingerprint(
    session_id: str,
    token: str,
    ts: float,
    diag_os: str | None,
    diag_user: str | None,
    diag_env: str | None,
) -> None:
    """Persist the X-Diag-* fingerprint headers sent by a compiled
    diagnostic binary when it calls back.  One row per callback hit,
    scoped to the session the callback token was minted for."""
    conn = get_connection()
    with write_lock():
        conn.execute(
            """
            INSERT INTO diagnostic_fingerprints
                (session_id, token, ts, diag_os, diag_user, diag_env)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, token, ts, diag_os, diag_user, diag_env),
        )
        conn.commit()


def get_diagnostic_fingerprints_bulk(
    session_ids: list[str],
) -> dict[str, list[sqlite3.Row]]:
    """Bulk fetch of diagnostic fingerprint rows per session, most-recent-
    first, unfiltered by since (caller applies its own cutoff).  One IN (...)
    query for a whole page instead of one per session_id."""
    if not session_ids:
        return {}
    conn = get_connection()
    placeholders = ",".join("?" for _ in session_ids)
    cur = conn.execute(
        f"""
        SELECT session_id, ts, diag_os, diag_user, diag_env
        FROM diagnostic_fingerprints
        WHERE session_id IN ({placeholders})
        ORDER BY session_id, ts DESC
        """,
        session_ids,
    )
    by_session: dict[str, list[sqlite3.Row]] = {sid: [] for sid in session_ids}
    for row in cur:
        by_session[row["session_id"]].append(row)
    return by_session


def diagnostic_fingerprints_from_rows(
    rows: list[sqlite3.Row], since: float | None
) -> list[dict[str, str | None]]:
    """Deduplicated diagnostic fingerprints from already-fetched rows,
    scoped to the current episode via `since`.  Returns a list of dicts
    with keys {os, user, env} in most-recent-first order, capped at 5."""
    seen: list[dict[str, str | None]] = []
    for row in rows:
        if since is not None and row["ts"] < since:
            continue
        fp = {"os": row["diag_os"], "user": row["diag_user"], "env": row["diag_env"]}
        # Deduplicate by (os, user) -- skip exact duplicates, keep distinct combos.
        key = (fp["os"], fp["user"])
        if any((d["os"], d["user"]) == key for d in seen):
            continue
        seen.append(fp)
        if len(seen) >= 5:
            break
    return seen

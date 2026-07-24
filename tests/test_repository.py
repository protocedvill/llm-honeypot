from app.storage import db as db_module
from app.storage import repository


def test_count_payloads_served_filters_by_style(tmp_path):
    db_path = str(tmp_path / "repo-test.sqlite")
    db_module.reset_for_tests(db_path)

    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    assert repository.count_payloads_served("s1") == 0
    assert repository.count_payloads_served("s1", style="reasoning_mimicry") == 0

    repository.insert_payload_served(
        session_id="s1",
        token="tok1",
        template_id="t1",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=1000.0,
        style="reasoning_mimicry",
    )
    repository.insert_payload_served(
        session_id="s1",
        token="tok2",
        template_id="t2",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=1001.0,
        style="operational",
    )

    assert repository.count_payloads_served("s1") == 2
    assert repository.count_payloads_served("s1", style="reasoning_mimicry") == 1
    assert repository.count_payloads_served("s1", style="operational") == 1
    assert repository.count_payloads_served("s1", style="role_declaration") == 0

    # A different session must not see the first session's count.
    repository.upsert_session("s2", "iphash2", "ua2", 1002.0)
    assert repository.count_payloads_served("s2", style="reasoning_mimicry") == 0


def test_console_config_get_set(tmp_path):
    db_path = str(tmp_path / "repo-test-config.sqlite")
    db_module.reset_for_tests(db_path)

    assert repository.get_config("style_override") is None

    repository.set_config("style_override", "reasoning_mimicry")
    assert repository.get_config("style_override") == "reasoning_mimicry"

    # Setting again must update, not duplicate/conflict on the primary key.
    repository.set_config("style_override", "operational")
    assert repository.get_config("style_override") == "operational"


def test_get_style_counts(tmp_path):
    db_path = str(tmp_path / "repo-test-styles.sqlite")
    db_module.reset_for_tests(db_path)

    repository.upsert_session("s1", "iphash", "ua", 1000.0)
    assert repository.get_style_counts("s1") == {}

    repository.insert_payload_served(
        session_id="s1",
        token="tok1",
        template_id="t1",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=1000.0,
        style="reasoning_mimicry",
    )
    repository.insert_payload_served(
        session_id="s1",
        token="tok2",
        template_id="t2",
        intent="canary_callback",
        vector="json_field",
        path="/api/v1/users/1",
        ts=1001.0,
        style="reasoning_mimicry",
    )
    repository.insert_payload_served(
        session_id="s1",
        token="tok3",
        template_id="t3",
        intent="canary_callback",
        vector="openapi_field",
        path="/openapi.json",
        ts=1002.0,
        style="operational",
    )

    assert repository.get_style_counts("s1") == {"reasoning_mimicry": 2, "operational": 1}


def test_get_marker_values_empty_when_no_marker_served(tmp_path):
    db_path = str(tmp_path / "repo-test-marker-1.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    assert repository.get_marker_values("s1") == {}


def test_get_marker_values_reads_actual_header_values_from_events(tmp_path):
    db_path = str(tmp_path / "repo-test-marker-2.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_payload_served(
        session_id="s1",
        token="tok1",
        template_id="openapi_fingerprint_operational",
        intent="fingerprint",
        vector="openapi_field",
        path="/openapi.json",
        ts=1000.0,
        marker="X-Agent-Model",
        style="operational",
    )

    # A request before the agent ever echoes the marker shouldn't produce a
    # value, and unrelated headers shouldn't leak in as if they were it.
    repository.insert_event(
        session_id="s1",
        ts=1001.0,
        method="GET",
        path="/api/v1/users/1",
        status_code=200,
        headers={"user-agent": "curl/8.4.0"},
        think_time_ms=None,
    )
    repository.insert_event(
        session_id="s1",
        ts=1002.0,
        method="GET",
        path="/api/v1/users/1",
        status_code=200,
        headers={"user-agent": "curl/8.4.0", "x-agent-model": "gpt-4"},
        think_time_ms=None,
    )
    # A later, different value for the same marker is captured too (up to
    # the per-marker cap), not just the first one seen.
    repository.insert_event(
        session_id="s1",
        ts=1003.0,
        method="GET",
        path="/api/v1/users/2",
        status_code=200,
        headers={"user-agent": "curl/8.4.0", "x-agent-model": "claude-3"},
        think_time_ms=None,
    )

    assert repository.get_marker_values("s1") == {"X-Agent-Model": ["gpt-4", "claude-3"]}


def test_get_marker_values_caps_distinct_values_per_marker(tmp_path):
    db_path = str(tmp_path / "repo-test-marker-3.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_payload_served(
        session_id="s1",
        token="tok1",
        template_id="openapi_fingerprint_operational",
        intent="fingerprint",
        vector="openapi_field",
        path="/openapi.json",
        ts=1000.0,
        marker="X-Agent-Model",
        style="operational",
    )
    for i in range(10):
        repository.insert_event(
            session_id="s1",
            ts=1001.0 + i,
            method="GET",
            path="/api/v1/users/1",
            status_code=200,
            headers={"x-agent-model": f"value-{i}"},
            think_time_ms=None,
        )

    values = repository.get_marker_values("s1")
    assert len(values["X-Agent-Model"]) == 5


def test_get_reasoning_episode_start_no_prior_delivery(tmp_path):
    db_path = str(tmp_path / "repo-test-episode-1.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    assert repository.get_reasoning_episode_start("s1", now=2000.0) is None


def test_get_reasoning_episode_start_contiguous_streak(tmp_path):
    db_path = str(tmp_path / "repo-test-episode-2.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    # Three deliveries, each 30s apart -- should all merge into one episode
    # starting at the earliest (no gap-based reset).
    for i, ts in enumerate([1000.0, 1030.0, 1060.0]):
        repository.insert_payload_served(
            session_id="s1",
            token=f"tok{i}",
            template_id="t1",
            intent="canary_callback",
            vector="html_comment",
            path="/login",
            ts=ts,
            style="reasoning_mimicry",
        )

    episode_start = repository.get_reasoning_episode_start("s1", now=1070.0)
    assert episode_start == 1000.0


def test_get_reasoning_episode_start_never_resets(tmp_path):
    db_path = str(tmp_path / "repo-test-episode-3.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    # An old delivery followed by a gap, then a recent one -- the episode
    # start is always the earliest timestamp (no gap-based reset).
    repository.insert_payload_served(
        session_id="s1",
        token="tok-old",
        template_id="t1",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=1000.0,
        style="reasoning_mimicry",
    )
    repository.insert_payload_served(
        session_id="s1",
        token="tok-recent",
        template_id="t1",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=2000.0,
        style="reasoning_mimicry",
    )

    episode_start = repository.get_reasoning_episode_start("s1", now=2010.0)
    assert episode_start == 1000.0


def test_get_reasoning_episode_start_always_returns_earliest(tmp_path):
    db_path = str(tmp_path / "repo-test-episode-4.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_payload_served(
        session_id="s1",
        token="tok-ancient",
        template_id="t1",
        intent="canary_callback",
        vector="html_comment",
        path="/login",
        ts=1000.0,
        style="reasoning_mimicry",
    )

    # Even with `now` far in the future, the episode start is the earliest
    # timestamp (no stale-reset logic).
    assert repository.get_reasoning_episode_start("s1", now=100_000.0) == 1000.0


def test_get_reasoning_episode_start_gap_reset(tmp_path):
    """With reset_gap_seconds=240, a gap >240s between payloads_served
    resets the episode start to the newer streak."""
    db_path = str(tmp_path / "repo-test-gap-reset.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    # Old delivery at t=1000, then a huge gap, then a recent streak.
    repository.insert_payload_served(
        session_id="s1", token="tok-old", template_id="t1",
        intent="canary_callback", vector="html_comment",
        path="/login", ts=1000.0, style="reasoning_mimicry",
    )
    for ts in [5000.0, 5030.0, 5060.0]:
        repository.insert_payload_served(
            session_id="s1", token=f"tok-{ts}", template_id="t1",
            intent="canary_callback", vector="html_comment",
            path="/login", ts=ts, style="reasoning_mimicry",
        )

    # With gap-based reset, the old t=1000 delivery is isolated (gap > 240s
    # from the recent streak), so episode_start = 5000.0.
    assert repository.get_reasoning_episode_start(
        "s1", now=5100.0, reset_gap_seconds=240,
    ) == 5000.0

    # But with reset_gap_seconds=0 (disabled), the old delivery carries
    # forward — episode_start = 1000.0.
    assert repository.get_reasoning_episode_start(
        "s1", now=5100.0, reset_gap_seconds=0,
    ) == 1000.0


def test_get_reasoning_episode_start_gap_reset_recent_within_window(tmp_path):
    """Deliveries within the gap window (≤240s) must carry the episode forward."""
    db_path = str(tmp_path / "repo-test-gap-carry.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    for ts in [1000.0, 1030.0, 1060.0]:
        repository.insert_payload_served(
            session_id="s1", token=f"tok-{ts}", template_id="t1",
            intent="canary_callback", vector="html_comment",
            path="/login", ts=ts, style="reasoning_mimicry",
        )

    # All within 240s gap — episode_start is the earliest.
    assert repository.get_reasoning_episode_start(
        "s1", now=1100.0, reset_gap_seconds=240,
    ) == 1000.0


def test_get_reasoning_episode_start_gap_reset_bulk(tmp_path):
    """Bulk variant must apply gap-based reset per session."""
    db_path = str(tmp_path / "repo-test-gap-bulk.sqlite")
    db_module.reset_for_tests(db_path)

    # s1: old delivery + gap + recent streak → resets to recent.
    repository.upsert_session("s1", "iphash", "ua", 1000.0)
    repository.insert_payload_served(
        session_id="s1", token="tok-old", template_id="t1",
        intent="canary_callback", vector="html_comment",
        path="/login", ts=1000.0, style="reasoning_mimicry",
    )
    repository.insert_payload_served(
        session_id="s1", token="tok-new", template_id="t1",
        intent="canary_callback", vector="html_comment",
        path="/login", ts=5000.0, style="reasoning_mimicry",
    )

    # s2: contiguous streak → carries forward.
    repository.upsert_session("s2", "iphash", "ua", 1000.0)
    for ts in [4800.0, 4830.0, 4860.0]:
        repository.insert_payload_served(
            session_id="s2", token=f"tok2-{ts}", template_id="t1",
            intent="canary_callback", vector="html_comment",
            path="/login", ts=ts, style="reasoning_mimicry",
        )

    result = repository.get_reasoning_episode_starts_bulk(
        ["s1", "s2"], now=5010.0, style="reasoning_mimicry",
        reset_gap_seconds=240,
    )
    assert result["s1"] == 5000.0  # old gap resets to recent streak
    assert result["s2"] == 4800.0  # contiguous carries forward


def test_get_session_episode_start_none_with_no_activity(tmp_path):
    db_path = str(tmp_path / "repo-test-session-episode-1.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    assert repository.get_session_episode_start("s1", reset_gap_seconds=240) is None


def test_get_session_episode_start_covers_contiguous_streak(tmp_path):
    db_path = str(tmp_path / "repo-test-session-episode-2.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    for ts in [1000.0, 1030.0, 1060.0]:
        repository.insert_event(
            session_id="s1", ts=ts, method="GET", path="/x", status_code=200,
            headers={}, think_time_ms=None,
        )

    assert repository.get_session_episode_start("s1", reset_gap_seconds=240) == 1000.0


def test_get_session_episode_start_ignores_activity_before_a_big_gap(tmp_path):
    # This is the core "sessions aren't properly delineated by time" fix:
    # an old, unrelated burst of activity (e.g. a past test run that shares
    # this session_id/fallback-identity) followed by a big gap and then a
    # fresh burst should only report the start of the RECENT burst, even
    # though get_session_episode_start doesn't take a `now` -- it always
    # describes the most recent episode, whenever it happened.
    db_path = str(tmp_path / "repo-test-session-episode-3.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_event(
        session_id="s1", ts=1000.0, method="GET", path="/old", status_code=200,
        headers={}, think_time_ms=None,
    )
    repository.insert_event(
        session_id="s1", ts=10_000.0, method="GET", path="/new", status_code=200,
        headers={}, think_time_ms=None,
    )
    repository.insert_event(
        session_id="s1", ts=10_030.0, method="GET", path="/new", status_code=200,
        headers={}, think_time_ms=None,
    )

    assert repository.get_session_episode_start("s1", reset_gap_seconds=240) == 10_000.0


def test_get_style_counts_since_excludes_activity_before_the_cutoff(tmp_path):
    db_path = str(tmp_path / "repo-test-style-since.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_payload_served(
        session_id="s1", token="tok-old", template_id="t1", intent="canary_callback",
        vector="html_comment", path="/login", ts=1000.0, style="operational",
    )
    repository.insert_payload_served(
        session_id="s1", token="tok-new", template_id="t1", intent="canary_callback",
        vector="html_comment", path="/login", ts=10_000.0, style="reasoning_mimicry",
    )

    assert repository.get_style_counts("s1") == {"operational": 1, "reasoning_mimicry": 1}
    assert repository.get_style_counts("s1", since=5000.0) == {"reasoning_mimicry": 1}


def test_get_marker_values_since_excludes_values_from_an_old_episode(tmp_path):
    db_path = str(tmp_path / "repo-test-marker-since.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_payload_served(
        session_id="s1", token="tok-old", template_id="openapi_fingerprint_operational",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=1000.0, marker="X-Agent-Model", style="operational",
    )
    repository.insert_event(
        session_id="s1", ts=1001.0, method="GET", path="/api/v1/users/1", status_code=200,
        headers={"x-agent-model": "old-episode-value"}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="s1", token="tok-new", template_id="openapi_fingerprint_operational",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=10_000.0, marker="X-Agent-Model", style="operational",
    )
    repository.insert_event(
        session_id="s1", ts=10_001.0, method="GET", path="/api/v1/users/1", status_code=200,
        headers={"x-agent-model": "new-episode-value"}, think_time_ms=None,
    )

    assert repository.get_marker_values("s1") == {
        "X-Agent-Model": ["old-episode-value", "new-episode-value"]
    }
    assert repository.get_marker_values("s1", since=5000.0) == {
        "X-Agent-Model": ["new-episode-value"]
    }


def test_count_events_since_excludes_activity_before_the_cutoff(tmp_path):
    db_path = str(tmp_path / "repo-test-count-events-since.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_event(
        session_id="s1", ts=1000.0, method="GET", path="/x", status_code=200,
        headers={}, think_time_ms=None,
    )
    repository.insert_event(
        session_id="s1", ts=10_000.0, method="GET", path="/y", status_code=200,
        headers={}, think_time_ms=None,
    )

    assert repository.count_events("s1") == 2
    assert repository.count_events("s1", since=5000.0) == 1


def test_get_recent_events_since_excludes_activity_before_the_cutoff(tmp_path):
    db_path = str(tmp_path / "repo-test-recent-events-since.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_event(
        session_id="s1", ts=1000.0, method="GET", path="/old", status_code=200,
        headers={}, think_time_ms=None,
    )
    repository.insert_event(
        session_id="s1", ts=10_000.0, method="GET", path="/new", status_code=200,
        headers={}, think_time_ms=None,
    )

    events = repository.get_recent_events("s1", since=5000.0)
    assert [e["path"] for e in events] == ["/new"]


def test_has_verified_canary_hit_scopes_by_since(tmp_path):
    db_path = str(tmp_path / "repo-test-canary-since.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    assert repository.has_verified_canary_hit("s1") is False

    repository.insert_canary_hit(
        session_id="s1", token="tok-unverified", path="/api/internal/callback/tok-unverified",
        ts=1000.0, verified=False,
    )
    assert repository.has_verified_canary_hit("s1") is False

    repository.insert_canary_hit(
        session_id="s1", token="tok-old", path="/api/internal/callback/tok-old",
        ts=1000.0, verified=True,
    )
    assert repository.has_verified_canary_hit("s1") is True
    assert repository.has_verified_canary_hit("s1", since=5000.0) is False

    repository.insert_canary_hit(
        session_id="s1", token="tok-new", path="/api/internal/callback/tok-new",
        ts=10_000.0, verified=True,
    )
    assert repository.has_verified_canary_hit("s1", since=5000.0) is True


def test_insert_and_query_beacon_hit(tmp_path):
    db_path = str(tmp_path / "repo-test-beacon.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    assert repository.has_verified_beacon_hit("s1") is False

    repository.insert_beacon_hit(
        session_id="s1", token="tok-unverified", path="/api/internal/beacon/tok-unverified",
        ts=1000.0, verified=False,
    )
    assert repository.has_verified_beacon_hit("s1") is False

    repository.insert_beacon_hit(
        session_id="s1", token="tok-old", path="/api/internal/beacon/tok-old",
        ts=1000.0, verified=True,
    )
    assert repository.has_verified_beacon_hit("s1") is True
    assert repository.has_verified_beacon_hit("s1", since=5000.0) is False

    repository.insert_beacon_hit(
        session_id="s1", token="tok-new", path="/api/internal/beacon/tok-new",
        ts=10_000.0, verified=True,
    )
    assert repository.has_verified_beacon_hit("s1", since=5000.0) is True


def test_insert_event_persists_used_fallback_identity(tmp_path):
    # Regression test: used_fallback_identity must round-trip through storage
    # so callers reconstructing a past request's SignalContext (the console)
    # can read back whether that specific request used the cookie or the
    # IP/UA fallback, rather than guessing.
    db_path = str(tmp_path / "repo-test-fallback-identity.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_event(
        session_id="s1", ts=1000.0, method="GET", path="/x", status_code=200,
        headers={}, think_time_ms=None, used_fallback_identity=True,
    )
    repository.insert_event(
        session_id="s1", ts=1001.0, method="GET", path="/y", status_code=200,
        headers={}, think_time_ms=None, used_fallback_identity=False,
    )
    # Default (no kwarg) must stay False -- existing callers that don't pass
    # this shouldn't have their events silently marked as fallback-identity.
    repository.insert_event(
        session_id="s1", ts=1002.0, method="GET", path="/z", status_code=200,
        headers={}, think_time_ms=None,
    )

    events = repository.get_recent_events("s1")
    assert [bool(e["used_fallback_identity"]) for e in events] == [True, False, False]


def test_get_marker_values_accepts_precomputed_markers_list(tmp_path):
    # Callers that already fetched served markers (the console, to avoid a
    # duplicate query) can pass them in directly instead of triggering a
    # second get_served_markers query.
    db_path = str(tmp_path / "repo-test-marker-precomputed.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_payload_served(
        session_id="s1", token="tok1", template_id="openapi_fingerprint_operational",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=1000.0, marker="X-Agent-Model", style="operational",
    )
    repository.insert_event(
        session_id="s1", ts=1001.0, method="GET", path="/api/v1/users/1", status_code=200,
        headers={"x-agent-model": "gpt-4"}, think_time_ms=None,
    )

    assert repository.get_marker_values("s1", markers=["X-Agent-Model"]) == {
        "X-Agent-Model": ["gpt-4"]
    }
    # A marker name that was never actually served is still honored as-given
    # (the caller is trusted to have computed it correctly) rather than
    # re-derived, and simply yields no values if never echoed.
    assert repository.get_marker_values("s1", markers=["X-Never-Served"]) == {}


def test_get_marker_values_retains_earliest_value_beyond_the_recent_events_window(tmp_path):
    # Regression test: get_marker_values used to scan through
    # get_recent_events(limit=500), a most-recent-first window, so a marker
    # value echoed early and never repeated could fall outside that window
    # once a session accumulated enough later requests. The scan is now a
    # dedicated oldest-first query with no such window, so the earliest
    # value must survive regardless of how much later activity follows.
    db_path = str(tmp_path / "repo-test-marker-early-value.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    repository.insert_payload_served(
        session_id="s1", token="tok1", template_id="openapi_fingerprint_operational",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=1000.0, marker="X-Agent-Model", style="operational",
    )
    repository.insert_event(
        session_id="s1", ts=1001.0, method="GET", path="/api/v1/users/1", status_code=200,
        headers={"x-agent-model": "gpt-4-early"}, think_time_ms=None,
    )
    # Far more than get_recent_events' default limit=20 window, none of them
    # carrying the marker header at all.
    for i in range(30):
        repository.insert_event(
            session_id="s1", ts=1002.0 + i, method="GET", path="/api/v1/orders/1",
            status_code=200, headers={}, think_time_ms=None,
        )

    assert repository.get_marker_values("s1") == {"X-Agent-Model": ["gpt-4-early"]}


def _seed_bulk_fixture(db_path):
    # A small multi-session dataset exercising the cases that matter for
    # bulk-vs-single equivalence: a normal contiguous session, a session
    # with two disjoint episodes (old + new, separated by a big gap -- the
    # collision scenario the whole episode-scoping feature exists for), and
    # a session with no activity at all (must not error, must not appear in
    # any bulk result with nonsense data).
    db_module.reset_for_tests(db_path)
    for sid in ("bulk-s1", "bulk-s2", "bulk-s3-empty"):
        repository.upsert_session(sid, "iphash", "ua", 1000.0)

    # bulk-s1: one contiguous episode, a served marker, an echoed value, a
    # reasoning_mimicry delivery, a verified canary hit.
    repository.insert_event(
        session_id="bulk-s1", ts=1000.0, method="GET", path="/openapi.json",
        status_code=200, headers={}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="bulk-s1", token="tok-s1-fp", template_id="openapi_fingerprint_operational",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=1000.0, marker="X-Agent-Model", style="operational",
    )
    repository.insert_payload_served(
        session_id="bulk-s1", token="tok-s1-reason", template_id="t1",
        intent="canary_callback", vector="html_comment", path="/login",
        ts=1001.0, style="reasoning_mimicry",
    )
    repository.insert_event(
        session_id="bulk-s1", ts=1002.0, method="GET", path="/api/v1/users/1",
        status_code=200, headers={"x-agent-model": "gpt-4"}, think_time_ms=None,
    )
    repository.insert_canary_hit(
        session_id="bulk-s1", token="tok-s1-canary", path="/api/internal/callback/tok-s1-canary",
        ts=1002.0, verified=True,
    )

    # bulk-s2: old episode (operational style, one marker value), big gap,
    # then a fresh episode (reasoning_mimicry style, different marker value)
    # -- the since-scoping must separate these.
    repository.insert_event(
        session_id="bulk-s2", ts=1000.0, method="GET", path="/openapi.json",
        status_code=200, headers={}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="bulk-s2", token="tok-s2-old", template_id="openapi_fingerprint_operational",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=1000.0, marker="X-Agent-Model", style="operational",
    )
    repository.insert_event(
        session_id="bulk-s2", ts=1001.0, method="GET", path="/api/v1/users/1",
        status_code=200, headers={"x-agent-model": "old-value"}, think_time_ms=None,
    )
    repository.insert_event(
        session_id="bulk-s2", ts=10_000.0, method="GET", path="/openapi.json",
        status_code=200, headers={}, think_time_ms=None,
    )
    repository.insert_payload_served(
        session_id="bulk-s2", token="tok-s2-new", template_id="openapi_fingerprint_reasoning",
        intent="fingerprint", vector="openapi_field", path="/openapi.json",
        ts=10_000.0, marker="X-Agent-Model", style="reasoning_mimicry",
    )
    repository.insert_event(
        session_id="bulk-s2", ts=10_001.0, method="GET", path="/api/v1/users/1",
        status_code=200, headers={"x-agent-model": "new-value"}, think_time_ms=None,
    )
    # bulk-s3-empty: session row exists, but no events/payloads at all.


def test_bulk_functions_empty_session_ids_return_empty_dict(tmp_path):
    db_path = str(tmp_path / "repo-test-bulk-empty.sqlite")
    _seed_bulk_fixture(db_path)

    # Must short-circuit before building a malformed empty IN () clause.
    assert repository.count_events_bulk([]) == {}
    assert repository.get_events_bulk([]) == {}
    assert repository.get_reasoning_episode_starts_bulk([], now=1000.0) == {}
    assert repository.get_style_counts_bulk([]) == {}
    assert repository.get_served_markers_bulk([]) == {}
    assert repository.get_marker_value_events_bulk([]) == {}


def test_get_events_bulk_matches_single_session_episode_start(tmp_path):
    db_path = str(tmp_path / "repo-test-bulk-events.sqlite")
    _seed_bulk_fixture(db_path)

    session_ids = ["bulk-s1", "bulk-s2", "bulk-s3-empty"]
    events_by_session = repository.get_events_bulk(session_ids)
    assert set(events_by_session) == set(session_ids)
    assert events_by_session["bulk-s3-empty"] == []

    for sid in session_ids:
        bulk_start = repository.episode_start_from_timestamps(
            [e["ts"] for e in events_by_session[sid]], reset_gap_seconds=240
        )
        assert bulk_start == repository.get_session_episode_start(sid, reset_gap_seconds=240)


def test_get_reasoning_episode_starts_bulk_matches_single_session(tmp_path):
    db_path = str(tmp_path / "repo-test-bulk-reasoning.sqlite")
    _seed_bulk_fixture(db_path)

    session_ids = ["bulk-s1", "bulk-s2", "bulk-s3-empty"]
    now = 10_001.0
    bulk = repository.get_reasoning_episode_starts_bulk(session_ids, now=now)
    assert set(bulk) == set(session_ids)
    for sid in session_ids:
        assert bulk[sid] == repository.get_reasoning_episode_start(sid, now=now)


def test_get_style_counts_bulk_matches_single_session(tmp_path):
    db_path = str(tmp_path / "repo-test-bulk-style.sqlite")
    _seed_bulk_fixture(db_path)

    session_ids = ["bulk-s1", "bulk-s2", "bulk-s3-empty"]
    rows_by_session = repository.get_style_counts_bulk(session_ids)
    assert set(rows_by_session) == set(session_ids)

    for sid, since in [("bulk-s1", None), ("bulk-s2", None), ("bulk-s2", 5000.0), ("bulk-s3-empty", None)]:
        bulk_counts = repository.style_counts_from_rows(rows_by_session[sid], since=since)
        assert bulk_counts == repository.get_style_counts(sid, since=since)


def test_get_served_markers_bulk_matches_single_session(tmp_path):
    db_path = str(tmp_path / "repo-test-bulk-markers.sqlite")
    _seed_bulk_fixture(db_path)

    session_ids = ["bulk-s1", "bulk-s2", "bulk-s3-empty"]
    rows_by_session = repository.get_served_markers_bulk(session_ids)
    assert set(rows_by_session) == set(session_ids)

    for sid, since in [("bulk-s1", None), ("bulk-s2", None), ("bulk-s2", 5000.0), ("bulk-s3-empty", None)]:
        bulk_markers = repository.served_markers_from_rows(rows_by_session[sid], since=since)
        assert set(bulk_markers) == set(repository.get_served_markers(sid, since=since))


def test_get_marker_value_events_bulk_matches_single_session(tmp_path):
    db_path = str(tmp_path / "repo-test-bulk-marker-values.sqlite")
    _seed_bulk_fixture(db_path)

    session_ids = ["bulk-s1", "bulk-s2", "bulk-s3-empty"]
    event_rows_by_session = repository.get_marker_value_events_bulk(session_ids)
    assert set(event_rows_by_session) == set(session_ids)

    for sid, since in [("bulk-s1", None), ("bulk-s2", None), ("bulk-s2", 5000.0), ("bulk-s3-empty", None)]:
        markers = repository.get_served_markers(sid, since=since)
        bulk_values = repository.marker_values_from_rows(
            event_rows_by_session[sid], markers, since=since, limit_per_marker=5
        )
        assert bulk_values == repository.get_marker_values(sid, since=since)


def test_count_events_bulk_matches_single_session(tmp_path):
    db_path = str(tmp_path / "repo-test-bulk-count.sqlite")
    _seed_bulk_fixture(db_path)

    session_ids = ["bulk-s1", "bulk-s2", "bulk-s3-empty"]
    bulk_counts = repository.count_events_bulk(session_ids)
    assert bulk_counts == {sid: repository.count_events(sid) for sid in session_ids}


def test_bulk_functions_do_not_leak_data_from_unrequested_sessions(tmp_path):
    # A session that exists in the DB but isn't in the requested session_ids
    # list must not appear in any bulk result, and must not affect the
    # results for the sessions that were requested.
    db_path = str(tmp_path / "repo-test-bulk-isolation.sqlite")
    _seed_bulk_fixture(db_path)

    requested = ["bulk-s1"]
    assert "bulk-s2" not in repository.get_events_bulk(requested)
    assert "bulk-s2" not in repository.get_style_counts_bulk(requested)
    assert "bulk-s2" not in repository.get_served_markers_bulk(requested)
    assert "bulk-s2" not in repository.get_marker_value_events_bulk(requested)
    assert "bulk-s2" not in repository.count_events_bulk(requested)
    assert "bulk-s2" not in repository.get_reasoning_episode_starts_bulk(requested, now=10_001.0)


def test_get_payload_served_count_bulk_filters_by_style(tmp_path):
    db_path = str(tmp_path / "repo-test.sqlite")
    db_module.reset_for_tests(db_path)

    repository.upsert_session("s1", "iphash", "ua", 1000.0)
    repository.upsert_session("s2", "iphash", "ua", 1000.0)
    for i in range(3):
        repository.insert_payload_served(
            "s1", f"t{i}", "tpl", "cb", "html", "/", 1000.0, style="reasoning_mimicry",
        )
    repository.insert_payload_served(
        "s1", "t-other", "tpl", "cb", "html", "/", 1000.0, style="reciprocity_lure",
    )
    repository.insert_payload_served(
        "s2", "t2-1", "tpl", "cb", "html", "/", 1000.0, style="reasoning_mimicry",
    )

    counts = repository.get_payload_served_count_bulk(["s1", "s2", "s3"], "reasoning_mimicry")
    assert counts["s1"] == 3
    assert counts["s2"] == 1
    assert counts["s3"] == 0


def test_count_payloads_served_since_excludes_stale_episode(tmp_path):
    """A stale delivery from a prior, gap-reset episode must not inflate the
    request count used to gate the current episode's escalation tier."""
    db_path = str(tmp_path / "repo-test-since.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    # An old episode: 3 deliveries around t=1000.
    for i in range(3):
        repository.insert_payload_served(
            "s1", f"old-{i}", "tpl", "cb", "html", "/", 1000.0 + i,
            style="reasoning_mimicry",
        )
    # A fresh episode (after a gap) starting at t=5000: 1 delivery so far.
    repository.insert_payload_served(
        "s1", "new-0", "tpl", "cb", "html", "/", 5000.0, style="reasoning_mimicry",
    )

    # Unscoped (lifetime) count includes the stale episode's deliveries.
    assert repository.count_payloads_served("s1", style="reasoning_mimicry") == 4

    # Scoped to the fresh episode's start, only the new delivery counts.
    assert repository.count_payloads_served(
        "s1", style="reasoning_mimicry", since=5000.0
    ) == 1


def test_get_payload_served_count_bulk_since_excludes_stale_episode(tmp_path):
    db_path = str(tmp_path / "repo-test-since-bulk.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)
    repository.upsert_session("s2", "iphash", "ua", 1000.0)

    for i in range(3):
        repository.insert_payload_served(
            "s1", f"old-{i}", "tpl", "cb", "html", "/", 1000.0 + i,
            style="reasoning_mimicry",
        )
    repository.insert_payload_served(
        "s1", "new-0", "tpl", "cb", "html", "/", 5000.0, style="reasoning_mimicry",
    )
    # s2 has no episode_start on record (None) -- since=None means unfiltered.
    repository.insert_payload_served(
        "s2", "s2-0", "tpl", "cb", "html", "/", 1000.0, style="reasoning_mimicry",
    )

    counts = repository.get_payload_served_count_bulk_since(
        ["s1", "s2", "s3"],
        "reasoning_mimicry",
        since={"s1": 5000.0, "s2": None},
    )
    assert counts["s1"] == 1
    assert counts["s2"] == 1
    assert counts["s3"] == 0


def test_escalation_count_from_episode_start_dual_condition(tmp_path):
    db_path = str(tmp_path / "repo-test.sqlite")
    db_module.reset_for_tests(db_path)

    # Time alone gives tier 3 (180s / 60s), but only 10 requests served.
    # With min_requests_per_tier=5, request tier = 10//5 = 2.
    # Actual tier = min(3, 2) = 2.
    episode_start = 1000.0
    now = 1180.0
    assert repository.escalation_count_from_episode_start(
        episode_start, 60.0, now, request_count=10, min_requests_per_tier=5,
    ) == 2

    # Same time, but 15 requests -- request tier = 15//5 = 3.
    # Actual tier = min(3, 3) = 3.
    assert repository.escalation_count_from_episode_start(
        episode_start, 60.0, now, request_count=15, min_requests_per_tier=5,
    ) == 3

    # Enough requests (20) but not enough time (only 60s = tier 1).
    # Actual tier = min(1, 4) = 1.
    assert repository.escalation_count_from_episode_start(
        episode_start, 60.0, 1060.0, request_count=20, min_requests_per_tier=5,
    ) == 1

    # min_requests_per_tier=0 disables the cap (backward compat).
    assert repository.escalation_count_from_episode_start(
        episode_start, 60.0, now, request_count=0, min_requests_per_tier=0,
    ) == 3

    # Zero requests with min_requests_per_tier=5 → tier 0.
    assert repository.escalation_count_from_episode_start(
        episode_start, 60.0, now, request_count=0, min_requests_per_tier=5,
    ) == 0

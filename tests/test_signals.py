from app.detection.signals import (
    SignalContext,
    bursty_agentic_timing_signal,
    curated_wordlist_recall_signal,
    marker_reference_signal,
    vuln_probe_signal,
    waf_trigger_signal,
)

_BASE = dict(
    headers={"user-agent": "curl/8.4.0"},
    method="GET",
    path="/login",
    ip="203.0.113.5",
    session_id="s1",
    ts=1000.0,
)


def _ctx(**overrides):
    base = dict(_BASE)
    base.update(overrides)
    return SignalContext(**base)


def test_curated_wordlist_recall_fires_on_multi_stack_breadth():
    ctx = _ctx(
        path="/phpinfo.php",
        prior_event_paths=["/.env", "/.git/config", "/web.config", "/.htaccess"],
        total_event_count=4,
    )
    assert curated_wordlist_recall_signal(ctx).ai > 0


def test_curated_wordlist_recall_silent_on_single_stack():
    ctx = _ctx(path="/.env", prior_event_paths=["/.git/config"], total_event_count=1)
    assert curated_wordlist_recall_signal(ctx).ai == 0


def test_curated_wordlist_recall_silent_on_large_request_count():
    # Breadth across a LARGE number of requests looks like a normal
    # brute-force wordlist sweep, not curated recall -- shouldn't fire. Uses
    # total_event_count (the session's real total), not the length of the
    # trailing-window path list, since that list is capped well below 30 by
    # get_recent_events() regardless of how long-lived the session actually is.
    many_paths = [f"/path{i}" for i in range(15)] + [
        "/.env",
        "/.git/config",
        "/web.config",
        "/.htaccess",
    ]
    ctx = _ctx(
        path="/phpinfo.php", prior_event_paths=many_paths, total_event_count=4000
    )
    assert curated_wordlist_recall_signal(ctx).ai == 0


def test_bursty_agentic_timing_fires_on_burst_plus_gap():
    ctx = _ctx(ts=1010.0, prior_event_timestamps=[1000.0, 1000.02, 1000.04])
    assert bursty_agentic_timing_signal(ctx).ai > 0


def test_bursty_agentic_timing_silent_on_uniform_human_cadence():
    ctx = _ctx(ts=1015.0, prior_event_timestamps=[1000.0, 1005.0, 1010.0])
    assert bursty_agentic_timing_signal(ctx).ai == 0


def test_bursty_agentic_timing_silent_on_pure_burst_no_gap():
    ctx = _ctx(ts=1000.06, prior_event_timestamps=[1000.0, 1000.02, 1000.04])
    assert bursty_agentic_timing_signal(ctx).ai == 0


def test_marker_reference_signal_fires():
    ctx = _ctx(is_marker_referenced=True)
    assert marker_reference_signal(ctx).ai > 0


def test_marker_reference_signal_silent_by_default():
    assert marker_reference_signal(_ctx()).ai == 0


def test_waf_trigger_signal_fires():
    ctx = _ctx(waf_triggered=True)
    assert waf_trigger_signal(ctx).bot == 2.5


def test_waf_trigger_signal_silent_by_default():
    assert waf_trigger_signal(_ctx()).bot == 0


def test_vuln_probe_signal_fires():
    ctx = _ctx(vuln_probe_detected=True)
    assert vuln_probe_signal(ctx).bot == 3.0


def test_vuln_probe_signal_silent_by_default():
    assert vuln_probe_signal(_ctx()).bot == 0

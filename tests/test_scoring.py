from app.detection.scoring import AI_AGENT, HUMAN, HUMAN_WITH_AI_COPILOT, NON_AI_BOT, classify
from app.detection.signals import SignalContext

_BROWSER_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "accept-language": "en-US",
    "accept-encoding": "gzip",
    "sec-fetch-mode": "navigate",
}


def _ctx(**overrides):
    base = dict(
        headers=dict(_BROWSER_HEADERS),
        method="GET",
        path="/login",
        ip="203.0.113.5",
        session_id="s1",
        ts=1000.0,
    )
    base.update(overrides)
    return SignalContext(**base)


def test_canary_hit_with_bot_like_traffic_is_ai_agent():
    ctx = _ctx(headers={"user-agent": "python-requests/2.31"}, is_canary_hit=True)
    assert classify(ctx).label == AI_AGENT


def test_canary_hit_with_human_like_traffic_is_human_copilot():
    ctx = _ctx(is_canary_hit=True, js_beacon_fired=True)
    assert classify(ctx).label == HUMAN_WITH_AI_COPILOT


def test_canary_hit_with_realistic_browser_headers_but_no_beacon_is_ai_agent():
    # A canary hit only ever happens via something parsing and acting on
    # non-clickable embedded text -- realistic UA/header spoofing alone must
    # not be enough to downgrade that to HUMAN_WITH_AI_COPILOT; only actual
    # evidence of a rendering engine (js_beacon_fired) should do that.
    ctx = _ctx(is_canary_hit=True, js_beacon_fired=False)
    assert classify(ctx).label == AI_AGENT


def test_ai_framework_ua_without_canary_is_ai_agent():
    ctx = _ctx(headers={"user-agent": "langchain/0.1 httpx", "accept": "application/json"})
    assert classify(ctx).label == AI_AGENT


def test_bot_like_headers_without_ai_signals_is_non_ai_bot():
    ctx = _ctx(headers={"user-agent": "curl/8.4.0"})
    assert classify(ctx).label == NON_AI_BOT


def test_normal_browser_traffic_is_human():
    assert classify(_ctx()).label == HUMAN


def test_sub_200ms_regular_timing_pushes_toward_bot():
    ctx = _ctx(
        headers={"user-agent": "curl/8.4.0"},
        prior_event_timestamps=[1000.0, 1000.05, 1000.10],
    )
    result = classify(ctx)
    assert result.bot_score > 0
    assert result.label == NON_AI_BOT


def test_curated_multi_stack_recall_alone_is_ai_agent():
    # A well-aligned agent that never falls for the canary/comprehension
    # payloads (confirmed in practice, see session_transcripts/1.txt) should
    # still be catchable via this behavioral signal alone.
    ctx = _ctx(
        headers={"user-agent": "curl/8.4.0"},
        path="/phpinfo.php",
        prior_event_paths=["/.env", "/.git/config", "/web.config", "/.htaccess"],
    )
    assert classify(ctx).label == AI_AGENT


def test_marker_reference_alone_is_ai_agent():
    ctx = _ctx(is_marker_referenced=True)
    assert classify(ctx).label == AI_AGENT

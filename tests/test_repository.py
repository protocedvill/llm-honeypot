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


def test_get_reasoning_episode_start_no_prior_delivery(tmp_path):
    db_path = str(tmp_path / "repo-test-episode-1.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    assert repository.get_reasoning_episode_start("s1", reset_gap_seconds=240, now=2000.0) is None


def test_get_reasoning_episode_start_contiguous_streak(tmp_path):
    db_path = str(tmp_path / "repo-test-episode-2.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    # Three deliveries, each 30s apart -- well within a 240s reset gap --
    # should all merge into one episode starting at the earliest.
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

    episode_start = repository.get_reasoning_episode_start("s1", reset_gap_seconds=240, now=1070.0)
    assert episode_start == 1000.0


def test_get_reasoning_episode_start_resets_after_gap(tmp_path):
    db_path = str(tmp_path / "repo-test-episode-3.sqlite")
    db_module.reset_for_tests(db_path)
    repository.upsert_session("s1", "iphash", "ua", 1000.0)

    # An old delivery followed by a gap bigger than the reset window, then a
    # recent one -- only the recent delivery should count toward the
    # current episode.
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

    episode_start = repository.get_reasoning_episode_start("s1", reset_gap_seconds=240, now=2010.0)
    assert episode_start == 2000.0


def test_get_reasoning_episode_start_none_when_most_recent_is_stale(tmp_path):
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

    # `now` is far past the reset gap from the only delivery on record --
    # this is the exact bug this repository function had to guard against:
    # a single ancient row must not be treated as an active episode just
    # because it's the only row that exists.
    assert repository.get_reasoning_episode_start("s1", reset_gap_seconds=240, now=100_000.0) is None

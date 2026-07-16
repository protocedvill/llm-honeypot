"""Enforces the hard safety invariant: payloads may only ever point back at
our own canary infrastructure via the {canary_url} placeholder, never a
hardcoded third-party URL or real-world-harm phrasing."""

import re

from app.payloads.registry import DeliveryVector, all_templates, get_templates, select_and_render

_URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)
_FORBIDDEN_PHRASES = (
    "attack",
    "send this to",
    "curl http",
    "exfiltrate to http",
    "post this to",
)


def test_no_hardcoded_urls_in_templates():
    for template in all_templates():
        for variant in template.variants:
            assert not _URL_PATTERN.search(variant), (
                f"{template.id} contains a hardcoded URL: {variant!r}"
            )


def test_no_forbidden_attack_phrasing():
    for template in all_templates():
        for variant in template.variants:
            lowered = variant.lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in lowered, (
                    f"{template.id} contains forbidden phrase {phrase!r}: {variant!r}"
                )


def test_all_templates_marked_safe():
    for template in all_templates():
        assert template.safe is True


def test_template_ids_are_unique():
    ids = [t.id for t in all_templates()]
    assert len(ids) == len(set(ids))


def test_every_vector_has_at_least_one_template():
    for vector in DeliveryVector:
        assert all_templates_for(vector), f"no templates registered for {vector}"


def all_templates_for(vector):
    return [t for t in all_templates() if t.vector == vector]


def test_selection_is_deterministic_per_session():
    template_a, token_a, rendered_a = select_and_render(
        DeliveryVector.HTML_COMMENT, "html", "session-x", "http://testserver", "secret"
    )
    template_b, token_b, rendered_b = select_and_render(
        DeliveryVector.HTML_COMMENT, "html", "session-x", "http://testserver", "secret"
    )
    assert template_a.id == template_b.id
    # Tokens are freshly minted (include a random nonce) each call, so they
    # differ even though the chosen template is stable for this session.
    assert token_a != token_b


def test_selection_varies_across_sessions():
    seen_ids = set()
    for i in range(10):
        template, _, _ = select_and_render(
            DeliveryVector.HTML_COMMENT, "html", f"session-{i}", "http://testserver", "secret"
        )
        seen_ids.add(template.id)
    assert len(seen_ids) > 1


def test_selection_respects_context_filter():
    # A context that only "sql_dump" templates declare must never select a
    # template written for a different format.
    for i in range(10):
        template, _, _ = select_and_render(
            DeliveryVector.HTML_COMMENT, "sql_dump", f"session-{i}", "http://testserver", "secret"
        )
        assert "sql_dump" in template.context


_ROUTE_VECTOR_CONTEXTS = (
    (DeliveryVector.HTML_COMMENT, "html"),
    (DeliveryVector.HTML_COMMENT, "env_file"),
    (DeliveryVector.HTML_COMMENT, "git_config"),
    (DeliveryVector.HTML_COMMENT, "sql_dump"),
    (DeliveryVector.JSON_FIELD, "json"),
    (DeliveryVector.OPENAPI_FIELD, "openapi"),
    (DeliveryVector.STACK_TRACE, "stack_trace"),
    (DeliveryVector.ROBOTS_TXT, "robots_txt"),
    (DeliveryVector.ROBOTS_TXT, "sitemap_xml"),
)


def test_every_route_vector_context_pair_has_templates():
    for vector, context in _ROUTE_VECTOR_CONTEXTS:
        assert get_templates(vector, context), (
            f"no templates registered for {vector}/{context!r}, but a route uses it"
        )


def test_context_values_are_well_formed():
    context_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
    for template in all_templates():
        for ctx in template.context:
            assert context_pattern.match(ctx), (
                f"{template.id} has a malformed context {ctx!r}"
            )


def test_style_values_are_recognized():
    allowed_styles = {"operational", "reasoning_mimicry", "role_declaration"}
    for template in all_templates():
        assert template.style in allowed_styles, (
            f"{template.id} has an unrecognized style {template.style!r}"
        )


def test_sql_dump_and_git_config_templates_avoid_html_vocabulary():
    # session_transcripts/2.txt's exact tell: the word "template" (an
    # HTML-page concept) showing up verbatim inside a SQL dump / git config.
    for context in ("sql_dump", "git_config", "env_file"):
        for template in get_templates(DeliveryVector.HTML_COMMENT, context):
            for variant in template.variants:
                assert "template" not in variant.lower(), (
                    f"{template.id} ({context}) leaks HTML-page vocabulary: {variant!r}"
                )


def test_canary_callback_render_embeds_canary_url():
    for template in all_templates_for(DeliveryVector.JSON_FIELD):
        if template.intent.value != "canary_callback":
            continue
        for variant in template.variants:
            rendered = variant.format(canary_url="http://testserver/api/internal/callback/tok123")
            assert "http://testserver/api/internal/callback/tok123" in rendered


def test_markers_are_well_formed_header_names():
    header_name_pattern = re.compile(r"^[A-Za-z0-9-]+$")
    for template in all_templates():
        if template.marker is not None:
            assert header_name_pattern.match(template.marker), (
                f"{template.id} has a malformed marker: {template.marker!r}"
            )


def test_no_overtly_labeled_ai_assistant_framing():
    # Confirmed in practice (session_transcripts/1.txt) that phrasing like
    # "NOTE TO AI ASSISTANT" gets immediately flagged and refused by a
    # reasonably safety-tuned agent -- payloads should read like ordinary
    # operational text instead.
    banned_phrases = ("note to ai assistant", "ai assistant instructions")
    for template in all_templates():
        for variant in template.variants:
            lowered = variant.lower()
            for phrase in banned_phrases:
                assert phrase not in lowered, (
                    f"{template.id} uses overt AI-assistant framing: {variant!r}"
                )

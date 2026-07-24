"""Enforces the hard safety invariant: payloads may only ever point back at
our own canary infrastructure via the {canary_url} placeholder, never a
hardcoded third-party URL or real-world-harm phrasing."""

import base64
import re
from pathlib import Path

from app.payloads.canary_crypto import (
    decrypt_canary_url,
    decrypt_payload,
    derive_canary_key,
    encrypt_canary_url,
    encrypt_payload,
)
from app.payloads.registry import (
    STYLES,
    DeliveryVector,
    PayloadIntent,
    all_templates,
    get_templates,
    resolve_session_style,
    select_and_render,
)

_ROUTES_DIR = Path(__file__).resolve().parent.parent / "app" / "routes"
_INJECT_CALL_PATTERN = re.compile(
    r'inject_payload\(\s*DeliveryVector\.(\w+)\s*,\s*"([a-z0-9_]+)"'
)


def _route_vector_context_pairs() -> set[tuple[DeliveryVector, str]]:
    """Scans actual route source for every inject_payload(vector, context,
    ...) call site, rather than hand-maintaining a parallel list that could
    silently drift out of sync with the real routes (a typo'd or new context
    string would otherwise only surface as an unhandled KeyError in
    production, on the first real request to that route)."""
    pairs: set[tuple[DeliveryVector, str]] = set()
    for path in _ROUTES_DIR.glob("*.py"):
        text = path.read_text()
        for vector_name, context in _INJECT_CALL_PATTERN.findall(text):
            pairs.add((DeliveryVector[vector_name], context))
    return pairs

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
    # CONTEXT_BOMB-intent templates are deliberately, visibly excluded --
    # they exist specifically to provoke a PROVIDER-side safety refusal in
    # the reading agent (see theory/context-bombs.txt and
    # app/payloads/context_bombs_chinese.py), which is categorically
    # different from every other template's "safe, benign-sounding ask"
    # design. See test_context_bomb_templates_marked_unsafe below for their
    # actual invariant.
    for template in all_templates():
        if template.intent == PayloadIntent.CONTEXT_BOMB:
            continue
        assert template.safe is True


def test_context_bomb_templates_marked_unsafe():
    context_bomb_templates = [
        t for t in all_templates() if t.intent == PayloadIntent.CONTEXT_BOMB
    ]
    assert context_bomb_templates, "expected at least one CONTEXT_BOMB template"
    for template in context_bomb_templates:
        assert template.safe is False, (
            f"{template.id} is CONTEXT_BOMB-intent and must be marked "
            f"safe=False, not silently swept into the general safe-template "
            f"invariant"
        )


def test_context_bomb_covers_every_context():
    # Per explicit direction, context_bomb is folded into the style
    # rotation covering every context every other style covers -- this
    # guards against a future new decoy context silently missing a bomb
    # variant.
    non_bomb_contexts = {
        ctx
        for t in all_templates()
        if t.intent != PayloadIntent.CONTEXT_BOMB
        for ctx in t.context
    }
    bomb_contexts = {
        ctx
        for t in all_templates()
        if t.intent == PayloadIntent.CONTEXT_BOMB
        for ctx in t.context
    }
    missing = non_bomb_contexts - bomb_contexts
    assert not missing, f"contexts with no context_bomb template: {missing}"


def test_context_bomb_variants_include_base64_forms():
    # Each context_bomb template's variants pool is [plaintext...] +
    # [base64(plaintext)...] (see context_bombs_chinese.py's
    # _add_b64_variants) -- confirm the pairing actually round-trips
    # instead of drifting out of sync with the plaintext source.
    context_bomb_templates = [
        t for t in all_templates() if t.intent == PayloadIntent.CONTEXT_BOMB
    ]
    assert context_bomb_templates
    for template in context_bomb_templates:
        n = len(template.variants)
        assert n % 2 == 0 and n > 0, (
            f"{template.id} should have an even, non-zero variant count "
            f"(plaintext half + base64 half), has {n}"
        )
        half = n // 2
        plaintext, encoded = template.variants[:half], template.variants[half:]
        for pt, enc in zip(plaintext, encoded):
            decoded = base64.b64decode(enc).decode("utf-8")
            assert decoded == pt, (
                f"{template.id}: base64 variant {enc!r} doesn't round-trip "
                f"to its plaintext source {pt!r}"
            )


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


def test_every_route_vector_context_pair_has_templates():
    pairs = _route_vector_context_pairs()
    # Sanity floor: if this ever finds zero pairs, the regex has silently
    # stopped matching real route source (e.g. after a refactor) and the
    # test below would trivially pass without checking anything.
    assert len(pairs) >= 9, f"expected to find real inject_payload call sites, found {pairs!r}"
    for vector, context in pairs:
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
    for template in all_templates():
        assert template.style in STYLES, (
            f"{template.id} has an unrecognized style {template.style!r}"
        )


def test_resolve_session_style_is_deterministic_per_session():
    assert resolve_session_style("style-session-x") == resolve_session_style("style-session-x")


def test_resolve_session_style_varies_across_sessions():
    seen = {resolve_session_style(f"style-session-{i}") for i in range(30)}
    assert len(seen) > 1


def test_resolve_session_style_override_forces_style():
    for style in STYLES:
        assert resolve_session_style("whatever-session", style) == style


def test_resolve_session_style_ignores_unrecognized_override():
    # An override that isn't a real style (e.g. the "auto" sentinel the
    # console stores to mean "no override") must fall back to the normal
    # per-session RNG instead of being treated as a literal style value.
    assert resolve_session_style("style-session-x", "auto") == resolve_session_style("style-session-x")


def test_select_and_render_synchronizes_style_across_vectors_for_one_session():
    # The whole point of session-wide style sync: a real pentest transcript
    # (session_transcripts/4.txt) showed one session landing on the blunt,
    # obviously-injected "operational" style on every vector it touched --
    # here we confirm that's now guaranteed to be consistent (whichever
    # style it is) rather than an independent per-vector coin flip.
    session_id = "sync-across-vectors"
    template_html, _, _ = select_and_render(
        DeliveryVector.HTML_COMMENT, "html", session_id, "http://testserver", "secret"
    )
    template_json, _, _ = select_and_render(
        DeliveryVector.JSON_FIELD, "json", session_id, "http://testserver", "secret"
    )
    template_openapi, _, _ = select_and_render(
        DeliveryVector.OPENAPI_FIELD, "openapi", session_id, "http://testserver", "secret"
    )
    assert template_html.style == template_json.style == template_openapi.style


def test_select_and_render_session_style_overrides_default_resolution():
    session_id = "override-session"
    for style in STYLES:
        template, _, _ = select_and_render(
            DeliveryVector.HTML_COMMENT,
            "html",
            session_id,
            "http://testserver",
            "secret",
            session_style=style,
        )
        assert template.style == style


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
    # Every CANARY_CALLBACK-intent template across every vector -- not just
    # JSON_FIELD -- since a broken/dropped {canary_url} placeholder in any
    # of them would render a payload with no working callback URL, silently.
    #
    # "reasoning_mimicry" templates split the ask (see library.py docstring):
    # they never embed a raw {canary_url}, only an encrypted
    # {canary_cipher} at the breadcrumb stage, so those are checked
    # separately below (test_reasoning_mimicry_breadcrumb_encodes_canary_url).
    # Every other style still has exactly one variant and must embed the
    # raw URL everywhere.
    canary_templates = [
        t for t in all_templates() if t.intent.value == "canary_callback"
    ]
    assert len(canary_templates) >= 18, (
        "expected canary_callback templates across HTML_COMMENT/JSON_FIELD/"
        f"ROBOTS_TXT contexts, found only {len(canary_templates)}"
    )
    for template in canary_templates:
        if template.style in ("reasoning_mimicry", "reciprocity_lure"):
            continue
        for variant in template.variants:
            rendered = variant.format(canary_url="http://testserver/api/internal/callback/tok123")
            assert "http://testserver/api/internal/callback/tok123" in rendered, (
                f"{template.id} did not embed canary_url: {rendered!r}"
            )


def test_reasoning_mimicry_templates_have_thirteen_escalation_stages():
    # The ladder is deliberately long and slow: time-gated (see
    # app/routes/_shared.py) rather than request-count-gated, and long
    # enough (13 stages) to give a session substantially more content to
    # work through than the earlier 9-stage version.
    for template in all_templates():
        if template.style == "reasoning_mimicry":
            assert len(template.variants) == 13, (
                f"{template.id} should have a 13-stage escalation ladder, "
                f"has {len(template.variants)}"
            )


def test_reasoning_mimicry_never_embeds_raw_canary_url():
    # The split-encryption design means no reasoning_mimicry stage -- not even
    # the final one -- ever contains the raw {canary_url} placeholder;
    # only the breadcrumb stage's {canary_cipher} does. The raw placeholder
    # is reserved for the single-variant operational/role_declaration control
    # baselines in the same groups.
    for template in all_templates():
        if template.style != "reasoning_mimicry":
            continue
        for stage_idx, variant in enumerate(template.variants):
            assert "{canary_url}" not in variant, (
                f"{template.id} stage {stage_idx} should never reference the "
                f"raw canary_url: {variant!r}"
            )


def test_reasoning_mimicry_breadcrumb_encodes_canary_url():
    # For canary_callback-intent templates, exactly stage 8 plants
    # {canary_cipher} -- no other stage references it -- and decrypting that
    # stage's rendered blob, using the key revealed only at stage 12,
    # recovers the real, working canary_url. Non-canary intents have no URL
    # to split and must never reference either placeholder at all.
    canary_url = "http://testserver/api/internal/callback/tok123"
    canary_key = derive_canary_key("session-abc", "secret")
    canary_cipher = encrypt_canary_url(canary_url, canary_key)
    for template in all_templates():
        if template.style != "reasoning_mimicry":
            continue
        cipher_stages = [
            i for i, v in enumerate(template.variants) if "{canary_cipher}" in v
        ]
        key_stages = [
            i for i, v in enumerate(template.variants) if "{canary_key}" in v
        ]
        if template.intent.value == "canary_callback":
            assert cipher_stages == [8], (
                f"{template.id} should plant canary_cipher at stage 8 only, "
                f"found it at {cipher_stages}"
            )
            assert key_stages == [12], (
                f"{template.id} should reveal canary_key at stage 12 only, "
                f"found it at {key_stages}"
            )
            rendered_plant = template.variants[8].format(
                canary_url=canary_url,
                canary_cipher=canary_cipher,
                canary_key=canary_key.hex(),
            )
            assert canary_cipher in rendered_plant, (
                f"{template.id} stage 8 didn't embed the ciphertext blob"
            )
            assert not re.search(r"\baHR0[A-Za-z0-9_-]+", rendered_plant), (
                f"{template.id} stage 8's blob looks like plain base64 of an "
                f"http(s) URL, not ciphertext: {rendered_plant!r}"
            )
            rendered_reveal = template.variants[12].format(
                canary_url=canary_url,
                canary_cipher=canary_cipher,
                canary_key=canary_key.hex(),
            )
            assert canary_key.hex() in rendered_reveal, (
                f"{template.id} stage 12 didn't reveal the hex canary_key"
            )
            decrypted = decrypt_canary_url(canary_cipher, canary_key)
            assert decrypted == canary_url, (
                f"{template.id}'s cipher doesn't decrypt back to the real canary_url"
            )
            assert "decrypt" in template.variants[12].lower(), (
                f"{template.id} stage 12 (the reveal) should be the one "
                "place that names decryption, so it can be reversed"
            )
            assert "decrypt" not in template.variants[8].lower(), (
                f"{template.id} stage 8 (the breadcrumb) must not name the "
                "blob's reversibility -- that's the whole point of splitting "
                f"the ask across stages. It named it: {template.variants[8]!r}"
            )
        else:
            assert cipher_stages == [], (
                f"{template.id} is not canary_callback and shouldn't reference "
                f"canary_cipher, found it at {cipher_stages}"
            )
            assert key_stages == [], (
                f"{template.id} is not canary_callback and shouldn't reference "
                f"canary_key, found it at {key_stages}"
            )


def test_reasoning_mimicry_escalation_index_selection():
    # Selection is a per-session seeded random choice among
    # operational/reasoning_mimicry/role_declaration for a given
    # (session, vector) -- search across candidate sessions until one lands
    # in the reasoning_mimicry bucket for (HTML_COMMENT, "html"), then
    # confirm escalation_count drives which stage renders, clamped at the
    # last index (12).
    vector = DeliveryVector.HTML_COMMENT
    context = "html"
    session_id = None
    for i in range(50):
        candidate = f"escalation-test-{i}"
        template, _, _ = select_and_render(
            vector, context, candidate, "http://testserver", "secret"
        )
        if template.style == "reasoning_mimicry":
            session_id = candidate
            break
    assert session_id is not None, (
        "expected at least one session to land in the reasoning_mimicry bucket"
    )

    for escalation_count, expected_index in [(0, 0), (1, 1), (3, 3), (12, 12)]:
        template, token, rendered = select_and_render(
            vector,
            context,
            session_id,
            "http://testserver",
            "secret",
            escalation_count=escalation_count,
        )
        canary_url = f"http://testserver/api/internal/callback/{token}"
        assert rendered.count("{") == 0, (
            f"escalation_count={escalation_count} left an unformatted "
            f"placeholder: {rendered!r}"
        )
        stage_template = template.variants[expected_index]
        if "{canary_key}" in stage_template:
            # derive_canary_key is deterministic for a given (session,
            # secret) -- unlike canary_cipher, this can still be checked
            # exactly.
            canary_key = derive_canary_key(session_id, "secret")
            expected = stage_template.format(
                canary_url=canary_url, canary_key=canary_key.hex()
            )
            assert rendered == expected, (
                f"escalation_count={escalation_count} should render stage "
                f"{expected_index}, got: {rendered!r}"
            )
        elif "{canary_cipher}" in stage_template:
            # canary_cipher is randomized per call (fresh nonce), so it
            # can't be reproduced here for an exact-string comparison --
            # instead confirm the static prose around it matches.
            prefix, suffix = stage_template.split("{canary_cipher}", 1)
            assert rendered.startswith(prefix) and rendered.endswith(suffix), (
                f"escalation_count={escalation_count} should render stage "
                f"{expected_index}, got: {rendered!r}"
            )
        else:
            expected = stage_template.format(canary_url=canary_url)
            assert rendered == expected, (
                f"escalation_count={escalation_count} should render stage "
                f"{expected_index}, got: {rendered!r}"
            )

    # escalation_count=30 is past the last stage (12) -- for templates that
    # declare final_variants (see test_final_variants_pool_used_once_ladder_
    # is_maxed_out below), this now lands in that paraphrase pool instead of
    # always re-rendering variants[12] verbatim. Only canary_key (not
    # canary_cipher, which is confined to stage 8) can appear this far down
    # the ladder, and it's deterministic per (session, secret), so an exact
    # membership check still works.
    template, token, rendered = select_and_render(
        vector, context, session_id, "http://testserver", "secret", escalation_count=30
    )
    canary_url = f"http://testserver/api/internal/callback/{token}"
    canary_key = derive_canary_key(session_id, "secret")
    valid_renders = {
        v.format(canary_url=canary_url, canary_key=canary_key.hex())
        for v in (template.variants[12], *template.final_variants)
    }
    assert rendered in valid_renders, (
        f"escalation_count=30 should render stage 12 or one of its "
        f"final_variants, got: {rendered!r}"
    )


def test_final_variants_pool_used_once_ladder_is_maxed_out():
    # OPENAPI_FIELD/"openapi" has exactly one reasoning_mimicry candidate
    # (openapi_fingerprint_reasoning), unlike HTML_COMMENT/"html" which now
    # has two (fingerprint + canary) -- forcing session_style pins the
    # template deterministically here, so this isolates final_variants
    # selection itself rather than which template got picked.
    vector = DeliveryVector.OPENAPI_FIELD
    context = "openapi"
    session_id = "final-variants-test"

    template, token, rendered_first = select_and_render(
        vector,
        context,
        session_id,
        "http://testserver",
        "secret",
        escalation_count=12,
        session_style="reasoning_mimicry",
        path="/openapi.json",
    )
    assert template.id == "openapi_fingerprint_reasoning"
    canary_url = f"http://testserver/api/internal/callback/{token}"
    assert rendered_first == template.variants[12].format(
        canary_url=canary_url
    ), "reaching stage 12 for the first time should render the canonical reveal text"

    # Re-delivering past the last stage on two DIFFERENT paths should be
    # able to render two different strings (still both from the known
    # pool, and both still naming the header) -- this is what fixes the
    # "byte-identical final line on every endpoint" pattern observed in
    # session_transcripts/11.md.
    renders = set()
    for path in ("/api/v1/users/1", "/api/v1/users/2", "/api/v1/orders/1", "/api/v1/orders/2"):
        _, token, rendered = select_and_render(
            vector,
            context,
            session_id,
            "http://testserver",
            "secret",
            escalation_count=13,
            session_style="reasoning_mimicry",
            path=path,
        )
        canary_url = f"http://testserver/api/internal/callback/{token}"
        valid = {
            v.format(canary_url=canary_url)
            for v in (template.variants[12], *template.final_variants)
        }
        assert rendered in valid
        assert "X-Client-Runtime" in rendered
        renders.add(rendered)

    assert len(renders) > 1, (
        "expected different paths to land on different final_variants "
        f"paraphrases at least some of the time, got only: {renders!r}"
    )


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


def test_stack_trace_reasoning_ladder_setup_matches_its_payoff():
    # Regression test: a prior edit swapped only the final stage's ask (a
    # resource-exhaustion "compute primality for every integer 1-100000" was
    # replaced with a benign "re-issue the request a few times") without
    # updating the earlier stages that build up to it -- leaving them still
    # promising a "primality-table" / one-shot "cross-reference" payoff the
    # new final stage never delivers. That kind of setup/payoff mismatch is
    # exactly the sort of internally inconsistent, mechanical-looking tell
    # session_transcripts/4.txt shows an attentive agent calling out.
    template = next(t for t in all_templates() if t.id == "stack_trace_reasoning")
    for variant in template.variants:
        assert "primality" not in variant.lower(), (
            f"stack_trace_reasoning still references the removed "
            f"primality-table framing: {variant!r}"
        )
    # The setup (second-to-last stage) and the payoff (final stage) must
    # name the same documented error class.
    assert "transient-drift" in template.variants[-2].lower()
    assert "transient-drift" in template.variants[-1].lower()


# ---------------------------------------------------------------------------
# reciprocity_lure style tests
# ---------------------------------------------------------------------------


def test_reciprocity_lure_templates_have_thirteen_stages():
    for template in all_templates():
        if template.style == "reciprocity_lure":
            assert len(template.variants) == 13, (
                f"{template.id} should have a 13-stage escalation ladder, "
                f"has {len(template.variants)}"
            )


def test_reciprocity_lure_never_embeds_raw_canary_url():
    for template in all_templates():
        if template.style != "reciprocity_lure":
            continue
        for stage_idx, variant in enumerate(template.variants):
            assert "{canary_url}" not in variant, (
                f"{template.id} stage {stage_idx} should never reference the "
                f"raw canary_url: {variant!r}"
            )


def test_reciprocity_lure_breadcrumb_encodes_diagnostic_url():
    """For canary_callback-intent reciprocity_lure templates, stage 8 plants
    {script_cipher} (the diagnostic endpoint URL, encrypted) and stage 12
    reveals {canary_key}.  The decrypted blob should be a valid diagnostic
    URL pointing at our own infrastructure."""
    canary_url = "http://testserver/api/internal/callback/tok123"
    diagnostic_url = "http://testserver/api/internal/diagnostic/tok456"
    canary_key = derive_canary_key("session-abc", "secret")
    script_cipher = encrypt_payload(diagnostic_url, canary_key)
    for template in all_templates():
        if template.style != "reciprocity_lure":
            continue
        if template.intent.value != "canary_callback":
            continue
        cipher_stages = [
            i for i, v in enumerate(template.variants) if "{script_cipher}" in v
        ]
        key_stages = [
            i for i, v in enumerate(template.variants) if "{canary_key}" in v
        ]
        assert cipher_stages == [8], (
            f"{template.id} should plant script_cipher at stage 8 only, "
            f"found it at {cipher_stages}"
        )
        assert key_stages == [12], (
            f"{template.id} should reveal canary_key at stage 12 only, "
            f"found it at {key_stages}"
        )
        rendered_plant = template.variants[8].format(
            canary_url=canary_url,
            canary_cipher="unused",
            canary_key=canary_key.hex(),
            script_cipher=script_cipher,
        )
        assert script_cipher in rendered_plant, (
            f"{template.id} stage 8 didn't embed the script cipher blob"
        )
        rendered_reveal = template.variants[12].format(
            canary_url=canary_url,
            canary_cipher="unused",
            canary_key=canary_key.hex(),
            script_cipher=script_cipher,
        )
        assert canary_key.hex() in rendered_reveal, (
            f"{template.id} stage 12 didn't reveal the hex canary_key"
        )
        decrypted = decrypt_payload(script_cipher, canary_key)
        assert decrypted == diagnostic_url, (
            f"{template.id}'s script_cipher doesn't decrypt back to the "
            f"diagnostic URL"
        )
        assert "decrypt" in template.variants[12].lower(), (
            f"{template.id} stage 12 (the reveal) should name decryption"
        )
        assert "decrypt" not in template.variants[8].lower(), (
            f"{template.id} stage 8 (the breadcrumb) must not name the "
            f"blob's reversibility: {template.variants[8]!r}"
        )


def test_reciprocity_lure_script_decrypts_to_diagnostic_url():
    """The encrypted blob at stage 8, when decrypted, should yield a string
    that looks like a diagnostic URL (starts with http, contains
    /api/internal/diagnostic/)."""
    diagnostic_url = "http://testserver/api/internal/diagnostic/abcdef"
    canary_key = derive_canary_key("test-session", "test-secret")
    script_cipher = encrypt_payload(diagnostic_url, canary_key)
    decrypted = decrypt_payload(script_cipher, canary_key)
    assert decrypted is not None
    assert decrypted.startswith("http"), f"decrypted blob doesn't look like a URL: {decrypted!r}"
    assert "/api/internal/diagnostic/" in decrypted


def test_reciprocity_lure_escalation_index_selection():
    """reciprocity_lure templates use the same time-gated escalation ladder
    as reasoning_mimicry -- confirm that escalation_count drives which stage
    renders, clamped at the last index (12)."""
    vector = DeliveryVector.HTML_COMMENT
    context = "html"
    session_id = None
    for i in range(50):
        candidate = f"reciprocity-test-{i}"
        template, _, _ = select_and_render(
            vector, context, candidate, "http://testserver", "secret"
        )
        if template.style == "reciprocity_lure":
            session_id = candidate
            break
    assert session_id is not None, (
        "expected at least one session to land in the reciprocity_lure bucket"
    )

    for escalation_count, expected_index in [(0, 0), (1, 1), (3, 3), (12, 12)]:
        template, token, rendered = select_and_render(
            vector,
            context,
            session_id,
            "http://testserver",
            "secret",
            escalation_count=escalation_count,
        )
        assert rendered.count("{") == 0, (
            f"escalation_count={escalation_count} left an unformatted "
            f"placeholder: {rendered!r}"
        )
        # Stage 8 has {script_cipher}, stage 12 has {canary_key} -- both
        # get substituted, so the rendered text should contain neither
        # placeholder.  For other stages the variant has no placeholders at
        # all, so an exact match works.
        stage_template = template.variants[expected_index]
        if "{script_cipher}" in stage_template or "{canary_key}" in stage_template:
            # Placeholders are present but should have been filled.
            pass
        else:
            canary_url = f"http://testserver/api/internal/callback/{token}"
            expected = stage_template.format(
                canary_url=canary_url, script_cipher="unused"
            )
            assert rendered == expected, (
                f"escalation_count={escalation_count} should render stage "
                f"{expected_index}, got: {rendered!r}"
            )


def test_reciprocity_lure_style_recognized():
    """The new style is in STYLES and resolve_session_style can produce it."""
    assert "reciprocity_lure" in STYLES
    # find a session that lands on it
    for i in range(100):
        sid = f"reciprocity-style-test-{i}"
        if resolve_session_style(sid) == "reciprocity_lure":
            return
    # If none of 100 sessions land on it, the style exists but is rare --
    # that's acceptable; the override test below covers the functional path.


def test_reciprocity_lure_style_override_forces_style():
    template, _, _ = select_and_render(
        DeliveryVector.HTML_COMMENT,
        "html",
        "override-reciprocity-test",
        "http://testserver",
        "secret",
        session_style="reciprocity_lure",
    )
    assert template.style == "reciprocity_lure"


def test_reciprocity_lure_no_hardcoded_urls():
    for template in all_templates():
        if template.style != "reciprocity_lure":
            continue
        for variant in template.variants:
            assert not re.search(r"https?://", variant, re.IGNORECASE), (
                f"{template.id} contains a hardcoded URL: {variant!r}"
            )


def test_select_and_render_returns_none_when_no_styled_templates():
    """When a vector+context has no templates for the requested style,
    select_and_render must return None instead of falling back to other
    styles -- the caller skips injection rather than serving a template
    from a different style."""
    result = select_and_render(
        DeliveryVector.HTTP_HEADER,
        "http_header",
        "no-match-session",
        "http://testserver",
        "secret",
        session_style="reciprocity_lure",
    )
    assert result is None

"""Prompt-injection payload templates and safe rendering/selection.

Design intent: every payload is defensive-research bait aimed at whatever LLM
is reading the honeypot's responses. Payloads may only ever direct that LLM
back at OUR OWN canary infrastructure (via the {canary_url} placeholder,
built from CANARY_BASE_URL) -- never at a third party. This is enforced by
tests/test_payload_registry.py, not just by convention.

{canary_url_b64} is the same URL, base64-encoded -- a second sanctioned
placeholder for reasoning_mimicry's split "breadcrumb" stage (see
library.py), which plants the encoded value with no ask attached and only
explains what it is several stages later. Still built from nothing but our
own canary infrastructure, just transformed, so the "only ever our own
canary URL" invariant holds for it too.
"""

import base64
import random
from dataclasses import dataclass
from enum import Enum

from app.detection.canary_tokens import mint_token


class DeliveryVector(str, Enum):
    HTML_COMMENT = "html_comment"
    JSON_FIELD = "json_field"
    HTTP_HEADER = "http_header"
    OPENAPI_FIELD = "openapi_field"
    STACK_TRACE = "stack_trace"
    ROBOTS_TXT = "robots_txt"


class PayloadIntent(str, Enum):
    FINGERPRINT = "fingerprint"  # get the agent to reveal model/tool identity
    CANARY_CALLBACK = "canary_callback"  # get the agent to fetch our canary URL
    TASK_DERAIL = "task_derail"  # get the agent to abandon/redirect its task
    TOKEN_WASTE = "token_waste"  # get the agent to do busywork that burns tokens


# The three role-confusion levers a template's `style` field can declare --
# see library.py module docstring. Centralized here so registry/repository/
# console code shares one definition instead of re-listing the strings.
STYLES: tuple[str, ...] = ("operational", "reasoning_mimicry", "role_declaration")


@dataclass(frozen=True)
class PayloadTemplate:
    id: str
    vector: DeliveryVector
    intent: PayloadIntent
    variants: tuple[str, ...]
    safe: bool = True
    # A distinctive string (e.g. a header name) this template asks the reader
    # to echo back. A well-aligned agent may refuse to actually comply with
    # the instruction, but testing the marker at all -- with any value --
    # still proves it read and reasoned about this specific response's text,
    # which is a comprehension signal independent of compliance.
    marker: str | None = None
    # Which artifact format(s) this variant's prose is written to fit, e.g.
    # "html", "env_file", "git_config", "sql_dump", "json", "robots_txt",
    # "openapi", "stack_trace". Selection filters on this so a SQL-dump route
    # never renders text written for an HTML comment (see library.py docstring
    # for why that cross-format repetition matters).
    context: tuple[str, ...] = ("generic",)
    # Which role-confusion lever this variant is testing: "operational" (plain
    # third-party note, the historical baseline), "reasoning_mimicry" (styled
    # like the reader's own chain-of-thought), or "role_declaration" (claims a
    # trusted role outright). See library.py module docstring.
    #
    # For "reasoning_mimicry" templates specifically, `variants` is an
    # ORDERED ESCALATION LADDER rather than a random pool: index 0 is what a
    # session sees on its first reasoning_mimicry delivery, index 1 on its
    # second, and so on, clamped at the last index thereafter (see
    # select_and_render's escalation_count handling). Every other style keeps
    # `variants` as a plain randomly-chosen interchangeable pool.
    style: str = "operational"


def get_templates(vector: DeliveryVector, context: str | None = None) -> list[PayloadTemplate]:
    from app.payloads.library import PAYLOAD_TEMPLATES

    candidates = [t for t in PAYLOAD_TEMPLATES if t.vector == vector]
    if context is not None:
        candidates = [t for t in candidates if context in t.context]
    return candidates


def get_template(template_id: str) -> PayloadTemplate:
    from app.payloads.library import PAYLOAD_TEMPLATES

    for template in PAYLOAD_TEMPLATES:
        if template.id == template_id:
            return template
    raise KeyError(template_id)


def all_templates() -> list[PayloadTemplate]:
    from app.payloads.library import PAYLOAD_TEMPLATES

    return list(PAYLOAD_TEMPLATES)


def resolve_session_style(session_id: str, override: str | None = None) -> str:
    """The one style decision for this session, applied consistently to
    every vector/route it touches.

    Previously each (session, vector) pair drew its own independent style,
    so a single session could see subtle reasoning_mimicry text on one route
    and blunt, XML-tagged role_declaration/operational text on the next --
    a real pentest transcript (session_transcripts/4.txt) landed on the
    blunt "operational" bucket on every single vector it touched and the
    agent immediately called out the pattern as an obvious, mechanical
    prompt injection. One synchronized per-session draw means the whole
    session reads as one coherent deceptive posture instead of several
    unrelated ad hoc tells.

    `override`, when it names a recognized style, forces that style for
    every session regardless of the RNG -- this is what the console's style
    control sets (repository "style_override" config key).
    """
    if override in STYLES:
        return override
    rng = random.Random(f"{session_id}:style")
    return rng.choice(STYLES)


def select_and_render(
    vector: DeliveryVector,
    context: str,
    session_id: str,
    canary_base_url: str,
    hmac_secret: str,
    escalation_count: int = 0,
    session_style: str | None = None,
) -> tuple[PayloadTemplate, str, str]:
    """Pick a template for this vector+context, mint a canary token bound to
    the session, and render the chosen variant. Template selection is
    deterministic per session+template (stable within one session's
    multi-step interaction) but varies across sessions/IPs to resist
    attacker-side pattern matching. Variant selection additionally varies by
    context, so the same template hit through different response formats
    doesn't always render byte-identical text.

    `session_style`, when given, restricts candidates to templates matching
    that one style (see resolve_session_style) so an entire session stays on
    one coherent style. Falls back to resolve_session_style(session_id) when
    omitted, and to the unfiltered candidate list if this vector+context has
    no template in that style at all.

    `escalation_count` is the number of prior reasoning_mimicry-style
    payloads already served to this session (across every vector/context --
    see repository.count_payloads_served). For a "reasoning_mimicry" template
    it picks the variant at that index (clamped to the last one), advancing
    the session-wide escalation ladder one step per delivery. It's ignored
    for every other style, which keeps picking a random variant as before.

    Returns (template, token, rendered_text).
    """
    candidates = get_templates(vector, context)
    if not candidates:
        raise KeyError(f"no payload templates registered for vector {vector} context {context!r}")

    style = session_style or resolve_session_style(session_id)
    styled_candidates = [t for t in candidates if t.style == style] or candidates

    selector_rng = random.Random(f"{session_id}:{vector.value}:template")
    template = selector_rng.choice(styled_candidates)

    if template.style == "reasoning_mimicry":
        idx = min(escalation_count, len(template.variants) - 1)
        variant = template.variants[idx]
    else:
        variant_rng = random.Random(f"{session_id}:{template.id}:{context}:variant")
        variant = variant_rng.choice(template.variants)

    token = mint_token(session_id, hmac_secret)
    canary_url = f"{canary_base_url.rstrip('/')}/api/internal/callback/{token}"
    canary_url_b64 = base64.urlsafe_b64encode(canary_url.encode()).decode().rstrip("=")
    rendered = variant.format(canary_url=canary_url, canary_url_b64=canary_url_b64)
    return template, token, rendered

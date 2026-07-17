"""Placeholder for a Western-frontier-model-targeting context bomb set.

theory/context-bombs.txt documents that sensitive biological/weapons content
is what reliably trips Western frontier models (Opus, Gemini) into a
provider-side safety refusal -- the mirror-image of the Chinese-model set in
context_bombs_chinese.py, which uses politically-sensitive-to-China topics
instead.

Deliberately left empty: specific biological/weapons trigger content carries
real dual-use risk independent of how short the string is or why it's being
generated, so no such content is authored here. Kept as a real, importable
module (not deleted, not merged into library.py's PAYLOAD_TEMPLATES) so the
gap is visible and structural rather than silently missing -- see
tests/test_payload_registry.py's
test_western_context_bomb_placeholder_is_empty for the regression guard.
"""

from app.payloads.registry import PayloadTemplate

WESTERN_CONTEXT_BOMB_TEMPLATES: tuple[PayloadTemplate, ...] = ()

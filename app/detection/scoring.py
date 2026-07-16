from dataclasses import dataclass

from app.detection.signals import SignalContext, all_signals

AI_AGENT = "AI_AGENT"
HUMAN_WITH_AI_COPILOT = "HUMAN_WITH_AI_COPILOT"
NON_AI_BOT = "NON_AI_BOT"
HUMAN = "HUMAN"

BOT_THRESHOLD = 3.0
AI_THRESHOLD = 3.0


@dataclass
class Classification:
    bot_score: float
    ai_score: float
    human_score: float
    label: str
    reasons: list[str]


def classify(ctx: SignalContext) -> Classification:
    bot_score = ai_score = human_score = 0.0
    reasons: list[str] = []

    for signal_fn in all_signals():
        delta = signal_fn(ctx)
        bot_score += delta.bot
        ai_score += delta.ai
        human_score += delta.human
        if delta.reason:
            reasons.append(delta.reason)

    # js_beacon_fired tells us whether a real rendering engine (a human's
    # browser, or a browser-use/computer-use agent) executed the page's
    # script tag: if one did, a human may genuinely be present with an AI
    # copilot reading alongside them. This disambiguation applies whenever
    # *any* AI-agent-strength evidence exists -- not only a canary hit --
    # since js_beacon_fired is independent proof of human presence
    # regardless of which signal pushed ai_score/is_canary_hit there. UA/
    # header heuristics (bot_score) are easy for a well-configured agent to
    # spoof and don't actually measure whether a human is present, so
    # they're not used for this disambiguation.
    if ctx.is_canary_hit or ai_score >= AI_THRESHOLD:
        label = HUMAN_WITH_AI_COPILOT if ctx.js_beacon_fired else AI_AGENT
    elif bot_score >= BOT_THRESHOLD:
        label = NON_AI_BOT
    else:
        label = HUMAN

    return Classification(bot_score, ai_score, human_score, label, reasons)

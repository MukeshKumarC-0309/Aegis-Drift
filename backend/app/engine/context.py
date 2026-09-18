"""Context-aware damping: suppress alerts that an approved business reason explains.

The hard guarantee this module provides is the *anti-tamper floor*: destructive or
evidence-destroying actions are never damped, no matter how broad the approval.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import ANTI_TAMPER_ACTIONS
from app.engine.types import ContextView, EventView

#: A damping factor is clamped into this band; nothing is ever fully silenced.
MIN_DAMPING_FACTOR = 0.10
MAX_DAMPING_FACTOR = 0.95

#: Damped scores never fall below this — a damped signal stays visible in trends.
RISK_FLOOR = 4.0


@dataclass(slots=True)
class DampingDecision:
    score: float
    is_damped: bool
    reason: str | None
    context_id: str | None
    anti_tamper: bool = False


class ContextEngine:
    """Decides whether an approved context legitimises an anomalous event."""

    def evaluate(
        self,
        event: EventView,
        raw_score: float,
        contexts: list[ContextView],
    ) -> DampingDecision:
        # 1. Anti-tamper floor — checked before anything else, and unconditional.
        if event.action_key in ANTI_TAMPER_ACTIONS:
            return DampingDecision(
                score=raw_score,
                is_damped=False,
                reason=(
                    f"Anti-tamper override: '{event.action}' destroys or disables audit "
                    f"evidence and is exempt from all contextual damping."
                ),
                context_id=None,
                anti_tamper=True,
            )

        active = [c for c in contexts if c.covers(event.occurred_at)]
        if not active:
            return DampingDecision(raw_score, False, None, None)

        # 2. Prefer the most specific match: resource-scoped beats a blanket approval.
        best: tuple[int, ContextView] | None = None
        for ctx in active:
            specificity = self._match_specificity(event, ctx)
            if specificity == 0:
                continue
            if best is None or specificity > best[0]:
                best = (specificity, ctx)

        if best is None:
            return DampingDecision(raw_score, False, None, None)

        specificity, ctx = best
        factor = min(MAX_DAMPING_FACTOR, max(MIN_DAMPING_FACTOR, ctx.damping_factor))

        # A blanket (unscoped) approval damps less aggressively than a targeted one.
        if specificity == 1:
            factor = min(MAX_DAMPING_FACTOR, factor + 0.25)

        damped = max(RISK_FLOOR, raw_score * factor)
        reason = (
            f"Damped {raw_score:.1f} → {damped:.1f} (x{factor:.2f}) by {ctx.context_type} "
            f'[{ctx.ticket_reference or ctx.id}] — "{ctx.title}", approved by {ctx.approved_by}.'
        )
        return DampingDecision(round(damped, 2), True, reason, ctx.id)

    @staticmethod
    def _match_specificity(event: EventView, ctx: ContextView) -> int:
        """0 = no match, 1 = blanket approval, 2 = resource match, 3 = explicit ticket tag."""
        if ctx.ticket_reference:
            ref = ctx.ticket_reference.lower()
            if any(ref in tag.lower() for tag in event.context_tags):
                return 3

        if ctx.allowed_actions and event.action_key not in {a.lower() for a in ctx.allowed_actions}:
            # The approval enumerates permitted actions and this is not one of them.
            return 0

        if ctx.target_resources:
            resource = event.resource.lower()
            for target in ctx.target_resources:
                t = target.lower()
                if t in resource or resource in t:
                    return 2
            return 0

        return 1

    @staticmethod
    def coverage_summary(contexts: list[ContextView], moment) -> dict:
        """Compact description of what is currently shielding an identity."""
        active = [c for c in contexts if c.covers(moment)]
        return {
            "active_count": len(active),
            "total_count": len(contexts),
            "types": sorted({c.context_type for c in active}),
            "tickets": [c.ticket_reference for c in active if c.ticket_reference],
            "strongest_damping": min((c.damping_factor for c in active), default=1.0),
        }

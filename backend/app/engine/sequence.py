"""Temporal sequence correlation — the core of low-and-slow detection.

A single event is rarely damning; a *trajectory* of small deviations is. This
module walks an identity's event stream in chronological order and maintains a
leaky risk accumulator:

    R(t_i) = R(t_{i-1}) · e^(−λ·Δt) + ΔR_i,     λ = ln2 / T½

Risk decays continuously toward a floor, so a burst of odd behaviour that stops
fades away, while sustained drift compounds into a state transition.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import pairwise

from app.core.enums import TransitionState
from app.engine.baseline import BaselineEngine
from app.engine.context import ContextEngine
from app.engine.rules import RuleEngine
from app.engine.types import (
    DEFAULT_VECTOR_WEIGHTS,
    BaselineView,
    ContextView,
    CorrelationResult,
    EventView,
    IndicatorView,
    PeerStats,
    ScoredEvent,
)

#: Risk never decays below this — a scored identity is never "absolutely zero".
RISK_FLOOR = 5.0

#: Per-event scores at or below this are treated as normal and do not accumulate.
DEFAULT_NORMAL_THRESHOLD = 28.0

#: Shape and gain of the accumulation curve. The exponent > 1 means a mildly odd
#: event contributes little while a severe one contributes disproportionately.
ACCUMULATION_EXPONENT = 1.18
ACCUMULATION_GAIN = 26.0

#: Consecutive anomalies compound. This is the whole premise of the platform: three
#: linked deviations are materially worse than three unrelated ones. Each additional
#: event in an unbroken streak adds this much multiplier, capped by STREAK_MAX_BONUS.
STREAK_STEP = 0.22
STREAK_MAX_BONUS = 1.1

#: A monotonically rising sensitivity tier across a streak is the signature of
#: deliberate escalation (recon -> access -> exfiltration) rather than noise.
ESCALATION_BONUS = 0.35

#: A single event severe enough to be damning on its own pins cumulative risk to at
#: least this level, so one catastrophic act is never averaged away by a quiet history.
SEVERITY_FLOORS: tuple[tuple[float, float], ...] = (
    (92.0, 76.0),
    (80.0, 56.0),
    (68.0, 34.0),
)


@dataclass(slots=True)
class EngineConfig:
    """Tunable hyperparameters, editable at runtime from the console."""

    decay_halflife_hours: float = 48.0
    normal_threshold: float = DEFAULT_NORMAL_THRESHOLD
    threshold_early_drift: float = 28.0
    threshold_escalating: float = 50.0
    threshold_critical: float = 75.0
    vector_weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_VECTOR_WEIGHTS))
    synergy_elevated_at: float = 45.0
    watchlist_multiplier: float = 1.0

    @property
    def lambda_decay(self) -> float:
        return math.log(2) / max(self.decay_halflife_hours, 0.25)

    def normalised_weights(self) -> dict[str, float]:
        """Weights always sum to 1 so a partial edit cannot silently rescale risk."""
        total = sum(self.vector_weights.values())
        if total <= 0:
            return dict(DEFAULT_VECTOR_WEIGHTS)
        return {k: v / total for k, v in self.vector_weights.items()}


class SequenceEngine:
    """Correlates a chronological event stream into a cumulative risk trajectory."""

    def __init__(
        self,
        baseline_engine: BaselineEngine,
        context_engine: ContextEngine,
        config: EngineConfig | None = None,
    ) -> None:
        self.baseline_engine = baseline_engine
        self.context_engine = context_engine
        self.config = config or EngineConfig()

    def correlate(
        self,
        identity_id: str,
        events: list[EventView],
        baseline: BaselineView,
        *,
        contexts: list[ContextView] | None = None,
        peer: PeerStats | None = None,
        rules: RuleEngine | None = None,
        indicators: dict[str, IndicatorView] | None = None,
        risk_multiplier: float = 1.0,
    ) -> CorrelationResult:
        cfg = self.config
        contexts = contexts or []
        rules = rules or RuleEngine([])

        if not events:
            return CorrelationResult(
                identity_id=identity_id,
                cumulative_risk=RISK_FLOOR,
                raw_cumulative_risk=RISK_FLOOR,
                transition_state=TransitionState.STABLE,
                drift_velocity=0.0,
                dominant_vectors=[],
                vector_scores=dict.fromkeys(cfg.vector_weights, 0.0),
                scored_events=[],
                matched_rule_ids=[],
                anti_tamper_triggered=False,
                damping_applied=False,
                damping_reasons=[],
                peak_risk=RISK_FLOOR,
                event_count=0,
            )

        ordered = sorted(events, key=lambda e: e.occurred_at)
        weights = cfg.normalised_weights()

        risk = RISK_FLOOR
        raw_risk = RISK_FLOOR
        peak = RISK_FLOOR
        last_time = ordered[0].occurred_at

        # Running per-day tallies feed the volume vector without a second pass.
        day_counts: dict[str, int] = defaultdict(int)
        day_bytes: dict[str, int] = defaultdict(int)

        # Decayed vector accumulator: recent anomalies dominate the attribution.
        vector_accum: dict[str, float] = dict.fromkeys(weights, 0.0)
        vector_weight_total = 0.0

        scored: list[ScoredEvent] = []
        streak = 0
        streak_sensitivities: list[int] = []
        matched_rule_ids: set[str] = set()
        damping_reasons: list[str] = []
        anti_tamper = False
        previous_auth: EventView | None = None

        for event in ordered:
            # 1. Time decay since the previous event.
            hours = max(0.0, (event.occurred_at - last_time).total_seconds() / 3600.0)
            decay = math.exp(-cfg.lambda_decay * hours)
            risk = max(RISK_FLOOR, risk * decay)
            raw_risk = max(RISK_FLOOR, raw_risk * decay)
            last_time = event.occurred_at

            day_key = event.occurred_at.date().isoformat()
            day_counts[day_key] += 1
            day_bytes[day_key] += event.bytes_transferred

            # 2. Per-event multi-vector scoring.
            vectors = self.baseline_engine.score_event(
                event,
                baseline,
                peer=peer,
                previous_event=previous_auth,
                rolling_day_count=day_counts[day_key],
                rolling_day_bytes=day_bytes[day_key],
                indicators=indicators,
            )
            if event.latitude is not None and event.longitude is not None:
                previous_auth = event

            # 3. Weighted fusion, plus a synergy bonus when several vectors fire at once.
            fused = sum(vectors.get(k, 0.0) * w for k, w in weights.items())
            elevated = sum(1 for v in vectors.values() if v >= cfg.synergy_elevated_at)
            if elevated >= 4:
                fused *= 1.45
            elif elevated == 3:
                fused *= 1.30
            elif elevated == 2:
                fused *= 1.14
            raw_event_score = min(100.0, fused * risk_multiplier)

            # 4. Declarative rules can add a bounded boost on top of the statistics.
            has_context = any(c.covers(event.occurred_at) for c in contexts)
            hits = rules.match(
                event,
                vectors,
                raw_event_score,
                cumulative_risk=risk,
                has_context=has_context,
            )
            if hits:
                raw_event_score = min(100.0, raw_event_score + RuleEngine.total_boost(hits))
                matched_rule_ids.update(r.id for r in hits)

            # 5. Context-aware damping (anti-tamper actions bypass it entirely).
            decision = self.context_engine.evaluate(event, raw_event_score, contexts)
            if decision.anti_tamper:
                anti_tamper = True
            if decision.is_damped and decision.reason:
                damping_reasons.append(decision.reason)

            # 6. Sequence amplification — an unbroken run of anomalies compounds.
            if raw_event_score > cfg.normal_threshold:
                streak += 1
                streak_sensitivities.append(event.sensitivity_level)
            else:
                streak = 0
                streak_sensitivities.clear()
            amplifier = self._streak_amplifier(streak, streak_sensitivities)

            # 7. Accumulate into the leaky integrator.
            raw_risk = max(
                self._accumulate(raw_risk, raw_event_score, cfg, amplifier),
                self._severity_floor(raw_event_score),
            )
            risk = max(
                self._accumulate(risk, decision.score, cfg, amplifier),
                self._severity_floor(decision.score),
            )
            peak = max(peak, risk)

            if raw_event_score > cfg.normal_threshold:
                # Weight attribution by how anomalous the event was, and decay old ones.
                influence = (raw_event_score - cfg.normal_threshold) / (100.0 - cfg.normal_threshold)
                for name in vector_accum:
                    vector_accum[name] = vector_accum[name] * decay + vectors.get(name, 0.0) * influence
                vector_weight_total = vector_weight_total * decay + influence

            state = self.classify(risk)
            scored.append(
                ScoredEvent(
                    event=event,
                    vector_scores=vectors,
                    raw_score=round(raw_event_score, 2),
                    damped_score=round(decision.score, 2),
                    is_damped=decision.is_damped,
                    damping_reason=decision.reason,
                    matched_rules=[r.slug for r in hits],
                    anti_tamper=decision.anti_tamper,
                    cumulative_risk=round(risk, 2),
                    raw_cumulative_risk=round(raw_risk, 2),
                    state=state,
                )
            )

        denom = max(vector_weight_total, 1e-6)
        vector_scores = {k: round(min(100.0, v / denom), 1) for k, v in vector_accum.items()}
        dominant = [
            name for name, value in sorted(vector_scores.items(), key=lambda kv: -kv[1]) if value >= 20.0
        ][:3] or ["nominal"]

        return CorrelationResult(
            identity_id=identity_id,
            cumulative_risk=round(risk, 2),
            raw_cumulative_risk=round(raw_risk, 2),
            transition_state=self.classify(risk),
            drift_velocity=self._velocity(scored),
            dominant_vectors=dominant,
            vector_scores=vector_scores,
            scored_events=scored,
            matched_rule_ids=sorted(matched_rule_ids),
            anti_tamper_triggered=anti_tamper,
            damping_applied=bool(damping_reasons),
            damping_reasons=damping_reasons[-3:],
            peak_risk=round(peak, 2),
            event_count=len(scored),
        )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _accumulate(current: float, event_score: float, cfg: EngineConfig, amplifier: float = 1.0) -> float:
        """Add one event's contribution to the accumulator, or bleed off if benign."""
        if event_score <= cfg.normal_threshold:
            # Normal behaviour actively rebuilds confidence.
            return max(RISK_FLOOR, current * 0.97)
        excess = (event_score - cfg.normal_threshold) / (100.0 - cfg.normal_threshold)
        delta = (excess**ACCUMULATION_EXPONENT) * ACCUMULATION_GAIN * amplifier
        return min(100.0, current + delta)

    @staticmethod
    def _severity_floor(event_score: float) -> float:
        """Lower bound the accumulator given one event's own severity."""
        for threshold, floor in SEVERITY_FLOORS:
            if event_score >= threshold:
                return floor
        return 0.0

    @staticmethod
    def _streak_amplifier(streak: int, sensitivities: list[int]) -> float:
        """Multiplier applied to a single event's risk contribution.

        Grows with the length of the current anomaly streak and gets an extra kick
        when the streak shows monotonically escalating data sensitivity.
        """
        if streak <= 1:
            return 1.0
        amp = 1.0 + min(STREAK_MAX_BONUS, STREAK_STEP * (streak - 1))
        tail = sensitivities[-4:]
        if len(tail) >= 3 and all(b >= a for a, b in pairwise(tail)) and tail[-1] > tail[0]:
            amp += ESCALATION_BONUS
        return amp

    def classify(self, risk: float) -> TransitionState:
        cfg = self.config
        if risk >= cfg.threshold_critical:
            return TransitionState.CRITICAL_TRANSITION
        if risk >= cfg.threshold_escalating:
            return TransitionState.ESCALATING
        if risk >= cfg.threshold_early_drift:
            return TransitionState.EARLY_DRIFT
        return TransitionState.STABLE

    @staticmethod
    def _velocity(scored: list[ScoredEvent]) -> float:
        """Risk change over the trailing 24 hours of the stream (points/day)."""
        if len(scored) < 2:
            return 0.0
        last = scored[-1]
        cutoff = last.event.occurred_at.timestamp() - 86400
        window = [s for s in scored if s.event.occurred_at.timestamp() >= cutoff]
        if len(window) < 2:
            window = scored[-6:]
        span_hours = max(
            (window[-1].event.occurred_at - window[0].event.occurred_at).total_seconds() / 3600.0,
            1.0,
        )
        delta = window[-1].cumulative_risk - window[0].cumulative_risk
        return round(delta * (24.0 / span_hours), 2)

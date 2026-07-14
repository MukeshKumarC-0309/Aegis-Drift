import math
from typing import List, Dict, Tuple, Optional, Any
from datetime import datetime, timedelta
from app.models import SecurityEvent, TransitionState, BaselineProfile
from app.engine.baseline import BaselineEngine
from app.engine.context import ContextAwareEngine


class SequenceCorrelationEngine:
    """
    Correlates behavioral anomalies across time using:
    1. Sliding-Window Exponential Decay Risk Accumulation
    2. Multi-Vector Non-Linear Synergistic Fusion
    3. Transition State Machine (STABLE -> EARLY_DRIFT -> ESCALATING -> CRITICAL_TRANSITION)
    4. Drift Velocity (rate of behavioral change over time)
    """

    def __init__(self, baseline_engine: BaselineEngine, context_engine: ContextAwareEngine):
        self.baseline_engine = baseline_engine
        self.context_engine = context_engine
        # Configurable hyperparameters
        self.decay_halflife_hours = 48.0  # 48-hour half-life
        self.lambda_decay = math.log(2) / self.decay_halflife_hours
        self.vector_weights = {
            "temporal": 0.20,
            "resource": 0.35,
            "privilege": 0.25,
            "peer_divergence": 0.20
        }
        self.normal_threshold = 28.0  # Events below 28 are considered normal/benign

    def correlate_event_stream(
        self,
        user_events: List[SecurityEvent],
        baseline: BaselineProfile
    ) -> Dict[str, Any]:
        """
        Processes a chronological stream of events for a user and calculates:
        - Temporal risk progression curve
        - Cumulative risk score
        - Transition state
        - Dominant anomaly vectors
        - Annotated timeline with detected deviations
        """
        if not user_events:
            return {
                "cumulative_risk": 5.0,
                "raw_cumulative_risk": 5.0,
                "transition_state": TransitionState.STABLE,
                "velocity": 0.0,
                "dominant_vectors": [],
                "timeline_points": [],
                "recent_vector_scores": {"temporal": 0.0, "resource": 0.0, "privilege": 0.0, "peer_divergence": 0.0}
            }

        # Sort chronologically
        sorted_events = sorted(user_events, key=lambda e: e.timestamp)
        timeline_points = []
        cumulative_risk = 5.0
        raw_cumulative_risk = 5.0
        last_time = sorted_events[0].timestamp

        vector_sums = {"temporal": 0.0, "resource": 0.0, "privilege": 0.0, "peer_divergence": 0.0}
        vector_counts = 0

        for idx, ev in enumerate(sorted_events):
            # 1. Time-based exponential decay
            hours_elapsed = max(0.0, (ev.timestamp - last_time).total_seconds() / 3600.0)
            decay_factor = math.exp(-self.lambda_decay * hours_elapsed)
            cumulative_risk = max(5.0, cumulative_risk * decay_factor)
            raw_cumulative_risk = max(5.0, raw_cumulative_risk * decay_factor)
            last_time = ev.timestamp

            # 2. Evaluate single event multi-vector anomaly
            v_scores = self.baseline_engine.evaluate_event_anomaly(ev, baseline)

            # 3. Multi-vector weighted fusion
            raw_event_score = (
                v_scores["temporal"] * self.vector_weights["temporal"] +
                v_scores["resource"] * self.vector_weights["resource"] +
                v_scores["privilege"] * self.vector_weights["privilege"] +
                v_scores["peer_divergence"] * self.vector_weights["peer_divergence"]
            )

            # Synergistic multi-vector penalty: if 2+ vectors are elevated (>45), add synergy multiplier
            elevated_vectors = sum(1 for score in v_scores.values() if score >= 45.0)
            if elevated_vectors >= 3:
                raw_event_score *= 1.35
            elif elevated_vectors == 2:
                raw_event_score *= 1.15

            raw_event_score = min(100.0, raw_event_score)

            # 4. Context-Aware Evaluation (Damping)
            damped_event_score, is_damped, damping_reason, matched_record = self.context_engine.evaluate_context(
                ev, raw_event_score
            )

            # 5. Incremental addition to cumulative risk accumulator
            # Normal events (< 28) do not increase risk, but reinforce confidence and decay risk towards 5.0
            if raw_event_score > self.normal_threshold:
                excess_raw = (raw_event_score - self.normal_threshold) / (100.0 - self.normal_threshold)
                delta_raw = (excess_raw ** 1.2) * 22.0
                raw_cumulative_risk = min(100.0, raw_cumulative_risk + delta_raw)

                # Accumulate vector weights only for anomalous signals
                for k in vector_sums:
                    vector_sums[k] = (vector_sums[k] * decay_factor) + v_scores[k]
                vector_counts += 1
            else:
                raw_cumulative_risk = max(5.0, raw_cumulative_risk * 0.98)

            if damped_event_score > self.normal_threshold:
                excess_damped = (damped_event_score - self.normal_threshold) / (100.0 - self.normal_threshold)
                delta_damped = (excess_damped ** 1.2) * 22.0
                cumulative_risk = min(100.0, cumulative_risk + delta_damped)
            else:
                cumulative_risk = max(5.0, cumulative_risk * 0.96)

            # Determine point state
            point_state = self._classify_state(cumulative_risk)

            timeline_points.append({
                "event_id": ev.id,
                "timestamp": ev.timestamp.isoformat(),
                "resource": ev.resource,
                "action": ev.action,
                "sensitivity": ev.sensitivity_level,
                "event_score": round(damped_event_score, 1),
                "raw_event_score": round(raw_event_score, 1),
                "cumulative_risk": round(cumulative_risk, 1),
                "raw_cumulative_risk": round(raw_cumulative_risk, 1),
                "is_damped": is_damped,
                "damping_reason": damping_reason,
                "state": point_state.value,
                "vector_breakdown": v_scores
            })

        # Calculate drift velocity: change in cumulative risk over last 24h of events
        velocity = 0.0
        if len(timeline_points) >= 6:
            velocity = round(timeline_points[-1]["cumulative_risk"] - timeline_points[-6]["cumulative_risk"], 1)

        # Dominant vectors
        sorted_vectors = sorted(vector_sums.items(), key=lambda x: x[1], reverse=True)
        dominant_vectors = [v[0] for v in sorted_vectors if v[1] > 5.0][:2]
        if not dominant_vectors:
            dominant_vectors = ["nominal"]

        final_state = self._classify_state(cumulative_risk)

        # Normalized recent vector scores [0-100]
        norm_vectors = {}
        denom = max(1.0, float(vector_counts))
        for k, val in vector_sums.items():
            norm_vectors[k] = min(100.0, round(val / denom, 1))

        return {
            "cumulative_risk": round(cumulative_risk, 1),
            "raw_cumulative_risk": round(raw_cumulative_risk, 1),
            "transition_state": final_state,
            "velocity": velocity,
            "dominant_vectors": dominant_vectors,
            "timeline_points": timeline_points,
            "recent_vector_scores": norm_vectors
        }

    def _classify_state(self, risk_score: float) -> TransitionState:
        if risk_score >= 75.0:
            return TransitionState.CRITICAL_TRANSITION
        elif risk_score >= 50.0:
            return TransitionState.ESCALATING
        elif risk_score >= 28.0:
            return TransitionState.EARLY_DRIFT
        else:
            return TransitionState.STABLE

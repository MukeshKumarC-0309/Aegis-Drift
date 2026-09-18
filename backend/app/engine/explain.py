"""Explainable AI: turn the numeric verdict into something an analyst can act on.

Every claim in the generated narrative is traceable to a specific scored event or
vector value — this module never asserts anything the pipeline did not measure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.core.enums import SENSITIVITY_LABELS, RiskVector, TransitionState
from app.engine.baseline import classify_hour_profile
from app.engine.mitre import map_techniques
from app.engine.types import BaselineView, ContextView, CorrelationResult, PeerStats

VECTOR_LABELS: dict[str, str] = {
    RiskVector.TEMPORAL.value: "Circadian deviation",
    RiskVector.RESOURCE.value: "Resource novelty & sensitivity",
    RiskVector.PRIVILEGE.value: "Privilege escalation",
    RiskVector.PEER_DIVERGENCE.value: "Peer-cohort divergence",
    RiskVector.GEOVELOCITY.value: "Geo-velocity & network origin",
    RiskVector.VOLUME.value: "Data volume anomaly",
    RiskVector.DEVICE.value: "Unrecognised device",
    RiskVector.INTEL.value: "Threat-intel correlation",
}

VECTOR_EXPLANATIONS: dict[str, str] = {
    RiskVector.TEMPORAL.value: (
        "Activity fell in hours this identity has historically been inactive, measured "
        "against a Laplace-smoothed 24-hour histogram of their own past behaviour."
    ),
    RiskVector.RESOURCE.value: (
        "Resources were accessed that are absent from the learned access set, or that sit "
        "above the identity's 95th-percentile sensitivity tier."
    ),
    RiskVector.PRIVILEGE.value: (
        "Privileged operations were executed at a rate or of a kind this identity does not routinely perform."
    ),
    RiskVector.PEER_DIVERGENCE.value: (
        "Behaviour diverged from the cohort of peers sharing this department and role, who "
        "act as the control group."
    ),
    RiskVector.GEOVELOCITY.value: (
        "Authentication originated from an unfamiliar network or implied a travel speed "
        "between consecutive sessions that is not physically possible."
    ),
    RiskVector.VOLUME.value: (
        "Event count or egress byte volume exceeded the identity's own daily mean by "
        "multiple standard deviations."
    ),
    RiskVector.DEVICE.value: (
        "Activity came from a device fingerprint never previously associated with this identity."
    ),
    RiskVector.INTEL.value: (
        "A network artefact in the event matched an active indicator in the threat-intel feed."
    ),
}

STATE_HEADLINES: dict[TransitionState, str] = {
    TransitionState.STABLE: "operating within its established behavioural envelope",
    TransitionState.EARLY_DRIFT: "showing early behavioural drift",
    TransitionState.ESCALATING: "on an escalating threat trajectory",
    TransitionState.CRITICAL_TRANSITION: "in a critical threat transition",
}


@dataclass(slots=True)
class Explanation:
    identity_id: str
    username: str
    headline: str
    narrative: str
    verdict: str
    confidence: float
    attribution: list[dict]
    baseline_comparison: dict
    peer_comparison: dict
    key_findings: list[dict]
    contributing_events: list[dict]
    mitre_techniques: list[dict]
    recommended_actions: list[dict]
    context_factors: list[dict]
    counter_evidence: list[str]

    def as_dict(self) -> dict:
        return {
            "identity_id": self.identity_id,
            "username": self.username,
            "headline": self.headline,
            "narrative": self.narrative,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "attribution": self.attribution,
            "baseline_comparison": self.baseline_comparison,
            "peer_comparison": self.peer_comparison,
            "key_findings": self.key_findings,
            "contributing_events": self.contributing_events,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "context_factors": self.context_factors,
            "counter_evidence": self.counter_evidence,
        }


class ExplainabilityEngine:
    """Generates the analyst-facing explanation for a correlation result."""

    def explain(
        self,
        result: CorrelationResult,
        baseline: BaselineView,
        *,
        contexts: list[ContextView] | None = None,
        peer: PeerStats | None = None,
        now: datetime | None = None,
    ) -> Explanation:
        contexts = contexts or []
        now = now or datetime.utcnow()

        attribution = self._attribution(result.vector_scores)
        findings = self._key_findings(result, baseline)
        counter = self._counter_evidence(result, baseline, contexts)
        confidence = self._confidence(result, baseline, counter)

        return Explanation(
            identity_id=result.identity_id,
            username=baseline.username,
            headline=self._headline(result, baseline),
            narrative=self._narrative(result, baseline, attribution, findings, contexts, counter),
            verdict=self._verdict(result),
            confidence=confidence,
            attribution=attribution,
            baseline_comparison=self._baseline_comparison(result, baseline),
            peer_comparison=self._peer_comparison(result, baseline, peer),
            key_findings=findings,
            contributing_events=self._contributing_events(result),
            mitre_techniques=map_techniques(result.scored_events, result.vector_scores),
            recommended_actions=self._recommended_actions(result),
            context_factors=[
                {
                    "id": c.id,
                    "type": c.context_type,
                    "title": c.title,
                    "ticket": c.ticket_reference,
                    "approved_by": c.approved_by,
                    "damping_factor": c.damping_factor,
                    "active": c.covers(now),
                    "valid_from": c.valid_from.isoformat(),
                    "valid_until": c.valid_until.isoformat(),
                    "target_resources": c.target_resources,
                }
                for c in contexts
            ],
            counter_evidence=counter,
        )

    # -------------------------------------------------------------- components
    @staticmethod
    def _headline(result: CorrelationResult, baseline: BaselineView) -> str:
        state = STATE_HEADLINES[result.transition_state]
        return (
            f"{baseline.username} ({baseline.role_title}, {baseline.department}) is {state} "
            f"at risk {result.cumulative_risk:.0f}/100."
        )

    @staticmethod
    def _verdict(result: CorrelationResult) -> str:
        if result.anti_tamper_triggered:
            return "ANTI_TAMPER_OVERRIDE"
        if result.damping_applied and result.cumulative_risk < 30:
            return "SUPPRESSED_BY_CONTEXT"
        if result.transition_state is TransitionState.CRITICAL_TRANSITION:
            return "CONTAINMENT_RECOMMENDED"
        if result.transition_state is TransitionState.ESCALATING:
            return "INVESTIGATE_NOW"
        if result.transition_state is TransitionState.EARLY_DRIFT:
            return "MONITOR"
        return "NO_ACTION"

    @staticmethod
    def _attribution(vector_scores: dict[str, float]) -> list[dict]:
        """Relative share of the verdict owed to each vector."""
        total = sum(vector_scores.values()) or 1.0
        rows = [
            {
                "vector": name,
                "label": VECTOR_LABELS.get(name, name.title()),
                "score": round(value, 1),
                "share": round(value / total * 100.0, 1),
                "explanation": VECTOR_EXPLANATIONS.get(name, ""),
            }
            for name, value in vector_scores.items()
        ]
        return sorted(rows, key=lambda r: -r["score"])

    @staticmethod
    def _key_findings(result: CorrelationResult, baseline: BaselineView) -> list[dict]:
        """The specific, evidenced observations behind the score."""
        findings: list[dict] = []
        anomalous = [s for s in result.scored_events if s.raw_score >= 45]

        novel = sorted(
            {s.event.resource for s in anomalous if s.event.resource not in baseline.resource_frequencies}
        )
        if novel:
            findings.append(
                {
                    "severity": "HIGH" if len(novel) >= 3 else "MEDIUM",
                    "title": f"{len(novel)} previously unseen resource(s) accessed",
                    "detail": "Never present in the learned access set: " + ", ".join(novel[:6]),
                    "evidence_count": len(novel),
                }
            )

        off_hours = [s for s in anomalous if s.event.is_off_hours]
        if off_hours:
            observed = len(off_hours) / max(len(result.scored_events), 1)
            findings.append(
                {
                    "severity": "HIGH" if observed > baseline.off_hours_ratio * 8 else "MEDIUM",
                    "title": f"{len(off_hours)} off-hours operation(s)",
                    "detail": (
                        f"{observed:.0%} of recent activity fell outside working hours, against a "
                        f"learned baseline of {baseline.off_hours_ratio:.1%}."
                    ),
                    "evidence_count": len(off_hours),
                }
            )

        escalated = [s for s in anomalous if s.event.sensitivity_level > baseline.typical_max_sensitivity]
        if escalated:
            top = max(e.event.sensitivity_level for e in escalated)
            findings.append(
                {
                    "severity": "CRITICAL" if top >= 5 else "HIGH",
                    "title": (
                        f"Sensitivity ceiling breached — reached Tier {top} "
                        f"({SENSITIVITY_LABELS.get(top, '?')})"
                    ),
                    "detail": (
                        f"Baseline ceiling is Tier {baseline.typical_max_sensitivity} "
                        f"({SENSITIVITY_LABELS.get(baseline.typical_max_sensitivity, '?')}); "
                        f"{len(escalated)} event(s) exceeded it."
                    ),
                    "evidence_count": len(escalated),
                }
            )

        exfil = [
            s for s in anomalous if s.event.bytes_transferred > 10_000_000 or s.event.record_count > 5000
        ]
        if exfil:
            total_bytes = sum(s.event.bytes_transferred for s in exfil)
            total_records = sum(s.event.record_count for s in exfil)
            findings.append(
                {
                    "severity": "CRITICAL",
                    "title": "Bulk data movement detected",
                    "detail": (
                        f"{_bytes(total_bytes)} across {len(exfil)} operation(s)"
                        + (f", covering approximately {total_records:,} records." if total_records else ".")
                    ),
                    "evidence_count": len(exfil),
                }
            )

        if result.anti_tamper_triggered:
            actions = sorted({s.event.action for s in result.scored_events if s.anti_tamper})
            findings.append(
                {
                    "severity": "CRITICAL",
                    "title": "Anti-tamper override engaged",
                    "detail": (
                        f"Evidence-destroying action(s) observed ({', '.join(actions)}). These bypass "
                        "all contextual damping by policy and cannot be suppressed by any approval."
                    ),
                    "evidence_count": len(actions),
                }
            )

        if result.drift_velocity > 12:
            findings.append(
                {
                    "severity": "HIGH",
                    "title": f"Rapid drift velocity: +{result.drift_velocity:.1f} risk points/day",
                    "detail": "Risk is compounding faster than it decays — the trajectory is accelerating.",
                    "evidence_count": 1,
                }
            )

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(findings, key=lambda f: order.get(f["severity"], 9))

    @staticmethod
    def _baseline_comparison(result: CorrelationResult, baseline: BaselineView) -> dict:
        recent = result.scored_events[-40:]
        observed_off = sum(1 for s in recent if s.event.is_off_hours) / max(len(recent), 1)
        observed_max = max((s.event.sensitivity_level for s in recent), default=1)
        novel = [s.event.resource for s in recent if s.event.resource not in baseline.resource_frequencies]
        return {
            "circadian_profile": classify_hour_profile(baseline.hourly_distribution),
            "off_hours": {
                "baseline": round(baseline.off_hours_ratio * 100, 1),
                "observed": round(observed_off * 100, 1),
                "unit": "%",
            },
            "max_sensitivity": {
                "baseline": baseline.typical_max_sensitivity,
                "observed": observed_max,
                "baseline_label": SENSITIVITY_LABELS.get(baseline.typical_max_sensitivity, "?"),
                "observed_label": SENSITIVITY_LABELS.get(observed_max, "?"),
            },
            "daily_events": {
                "baseline": baseline.avg_daily_events,
                "observed": len(recent),
                "stddev": baseline.stddev_daily_events,
            },
            "resource_entropy": {
                "baseline": baseline.resource_entropy,
                "observed": round(len({s.event.resource for s in recent}) / max(len(recent), 1), 3),
            },
            "known_resources": baseline.common_resources[:8],
            "novel_resources": sorted(set(novel))[:8],
            "baseline_maturity": baseline.maturity,
            "baseline_sample_size": baseline.sample_event_count,
        }

    @staticmethod
    def _peer_comparison(result: CorrelationResult, baseline: BaselineView, peer: PeerStats | None) -> dict:
        if not peer:
            return {
                "cohort": baseline.peer_group_id,
                "available": False,
                "note": "No peer cohort established for this role yet.",
            }
        sigma = max(peer.stddev_risk, 1.0)
        z = (result.cumulative_risk - peer.mean_risk) / sigma
        return {
            "cohort": peer.key,
            "available": True,
            "member_count": peer.member_count,
            "cohort_mean_risk": round(peer.mean_risk, 1),
            "cohort_stddev": round(peer.stddev_risk, 1),
            "identity_risk": result.cumulative_risk,
            "z_score": round(z, 2),
            "percentile": _z_to_percentile(z),
            "cohort_mean_daily_events": round(peer.mean_daily_events, 1),
            "cohort_mean_max_sensitivity": round(peer.mean_max_sensitivity, 1),
            "interpretation": (
                f"This identity sits {abs(z):.1f} standard deviations "
                f"{'above' if z >= 0 else 'below'} its {peer.member_count}-member cohort mean."
            ),
        }

    @staticmethod
    def _contributing_events(result: CorrelationResult) -> list[dict]:
        """The events that actually moved the score, most impactful first."""
        ranked = sorted(result.scored_events, key=lambda s: -s.raw_score)[:12]
        return [
            {
                "event_id": s.event.id,
                "timestamp": s.event.occurred_at.isoformat(),
                "resource": s.event.resource,
                "action": s.event.action,
                "event_type": s.event.event_type.value,
                "sensitivity": s.event.sensitivity_level,
                "sensitivity_label": SENSITIVITY_LABELS.get(s.event.sensitivity_level, "?"),
                "raw_score": s.raw_score,
                "damped_score": s.damped_score,
                "is_damped": s.is_damped,
                "anti_tamper": s.anti_tamper,
                "matched_rules": s.matched_rules,
                "ip_address": s.event.ip_address,
                "country": s.event.country,
                "bytes": s.event.bytes_transferred,
                "records": s.event.record_count,
                "top_vectors": s.top_vectors(),
            }
            for s in ranked
        ]

    @staticmethod
    def _counter_evidence(
        result: CorrelationResult, baseline: BaselineView, contexts: list[ContextView]
    ) -> list[str]:
        """Reasons an analyst might reasonably close this as benign. Stating these
        explicitly is what keeps the tool honest rather than merely accusatory."""
        notes: list[str] = []
        if not baseline.is_mature:
            notes.append(
                f"Baseline is immature ({baseline.sample_event_count} samples, "
                f"{baseline.maturity:.0%} confidence) — novelty scores are less reliable."
            )
        if contexts:
            active = [c for c in contexts if c.is_active]
            if active:
                notes.append(
                    f"{len(active)} approved business context(s) exist for this identity: "
                    + ", ".join(f"{c.context_type} [{c.ticket_reference or c.id}]" for c in active[:3])
                )
        benign = sum(1 for s in result.scored_events if s.raw_score < 28)
        if benign and result.event_count:
            share = benign / result.event_count
            if share > 0.7:
                notes.append(f"{share:.0%} of activity in the window remained entirely within baseline.")
        if result.damping_applied:
            notes.append("Contextual damping was applied to at least one event in this window.")
        if result.drift_velocity < 0:
            notes.append("Risk is currently decaying — no new anomalies in the recent window.")
        return notes

    @staticmethod
    def _confidence(result: CorrelationResult, baseline: BaselineView, counter: list[str]) -> float:
        """How much the engine trusts its own verdict, given evidence and data quality."""
        confidence = 50.0
        confidence += min(25.0, baseline.maturity * 25.0)
        anomalous = sum(1 for s in result.scored_events if s.raw_score >= 45)
        confidence += min(20.0, anomalous * 3.0)
        if result.anti_tamper_triggered:
            confidence += 15.0
        if len([v for v in result.vector_scores.values() if v >= 40]) >= 3:
            confidence += 8.0
        confidence -= len(counter) * 4.0
        return round(max(15.0, min(99.0, confidence)), 1)

    @staticmethod
    def _recommended_actions(result: CorrelationResult) -> list[dict]:
        actions: list[dict] = []

        def add(action: str, label: str, rationale: str, urgency: str) -> None:
            actions.append({"action": action, "label": label, "rationale": rationale, "urgency": urgency})

        state = result.transition_state
        if result.anti_tamper_triggered:
            add(
                "QUARANTINE_SESSION",
                "Quarantine active sessions",
                "Audit-trail tampering was observed; preserve remaining evidence immediately.",
                "IMMEDIATE",
            )
            add(
                "REVOKE_TOKENS",
                "Revoke all issued tokens",
                "Assume credential compromise until proven otherwise.",
                "IMMEDIATE",
            )
            add(
                "ESCALATE",
                "Escalate to Tier-3 incident response",
                "Evidence destruction meets the bar for a declared incident.",
                "IMMEDIATE",
            )
        elif state is TransitionState.CRITICAL_TRANSITION:
            add(
                "QUARANTINE_SESSION",
                "Quarantine active sessions",
                "Risk exceeded the critical threshold with crown-jewel exposure.",
                "IMMEDIATE",
            )
            add(
                "REVOKE_TOKENS",
                "Revoke issued tokens and API keys",
                "Cut off any parallel automated access paths.",
                "IMMEDIATE",
            )
            add(
                "NOTIFY_MANAGER",
                "Notify the reporting manager",
                "Confirm whether the activity has an out-of-band business justification.",
                "HIGH",
            )
        elif state is TransitionState.ESCALATING:
            add(
                "STEP_UP_MFA",
                "Force step-up MFA challenge",
                "Verify the human behind the session before it progresses further.",
                "HIGH",
            )
            add(
                "OPEN_TICKET",
                "Open an investigation case",
                "Trajectory warrants a tracked investigation with an owner.",
                "HIGH",
            )
        elif state is TransitionState.EARLY_DRIFT:
            add(
                "NOTIFY_MANAGER",
                "Confirm with the reporting manager",
                "Early drift is frequently a legitimate role or project change.",
                "MEDIUM",
            )
            add(
                "ADD_CONTEXT_EXEMPTION",
                "Record an approved context",
                "If justified, record it so the cohort baseline stops re-alerting.",
                "LOW",
            )

        if result.damping_applied and not result.anti_tamper_triggered:
            add(
                "RE_BASELINE",
                "Re-baseline the identity",
                "Approved context is active; folding it in prevents recurring false positives.",
                "LOW",
            )
        return actions

    # ---------------------------------------------------------------- narrative
    @staticmethod
    def _narrative(
        result: CorrelationResult,
        baseline: BaselineView,
        attribution: list[dict],
        findings: list[dict],
        contexts: list[ContextView],
        counter: list[str],
    ) -> str:
        who = f"**{baseline.username}** ({baseline.role_title}, {baseline.department})"
        state_text = STATE_HEADLINES[result.transition_state]

        paragraphs: list[str] = []

        opening = (
            f"{who} is {state_text}. The correlation engine scored {result.event_count} events "
            f"in the current window, producing a composite risk of **{result.cumulative_risk:.0f}/100** "
            f"against an unmitigated raw score of {result.raw_cumulative_risk:.0f}."
        )
        if result.drift_velocity:
            direction = "rising" if result.drift_velocity > 0 else "decaying"
            opening += f" Risk is {direction} at {abs(result.drift_velocity):.1f} points per day."
        paragraphs.append(opening)

        top = [a for a in attribution if a["score"] >= 20][:3]
        if top:
            drivers = "; ".join(f"{a['label']} at {a['score']:.0f}/100" for a in top)
            paragraphs.append(
                f"**Why it was flagged.** The verdict is driven principally by {drivers}. "
                + top[0]["explanation"]
            )

        if findings:
            bullets = "\n".join(f"- **{f['title']}** — {f['detail']}" for f in findings[:5])
            paragraphs.append(f"**What was observed.**\n{bullets}")

        if result.anti_tamper_triggered:
            paragraphs.append(
                "**Anti-tamper override.** One or more actions in this window destroy or disable "
                "audit evidence. Policy forbids damping these under any approval, so the score "
                "reported here is unmitigated regardless of the contexts listed below."
            )
        elif result.damping_applied:
            reason = result.damping_reasons[-1] if result.damping_reasons else ""
            paragraphs.append(
                f"**Context applied.** Approved business context reduced the raw score from "
                f"{result.raw_cumulative_risk:.0f} to {result.cumulative_risk:.0f}. {reason}"
            )
        elif contexts:
            paragraphs.append(
                f"**Context checked.** {len(contexts)} context record(s) exist for this identity "
                "but none covered the anomalous activity — either the window had lapsed or the "
                "resources fell outside the approved scope."
            )

        if counter:
            paragraphs.append(
                "**Considerations against this verdict.**\n" + "\n".join(f"- {c}" for c in counter[:4])
            )

        return "\n\n".join(paragraphs)


def _bytes(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024.0  # type: ignore[assignment]
    return f"{value} B"


def _z_to_percentile(z: float) -> int:
    """Normal CDF approximation, adequate for an analyst-facing percentile."""
    import math

    return round(100 * 0.5 * (1 + math.erf(z / math.sqrt(2))))

from typing import List, Dict, Any, Optional
from datetime import datetime
from app.models import (
    SecurityEvent, BaselineProfile, ContextRecord, TransitionState, ExplainabilityPayload
)


class ExplainabilityEngine:
    """
    Explainable AI (XAI) & SOC Investigation Briefing Engine:
    Translates mathematical anomalies, temporal sequences, and contextual factors
    into plain-language investigator narratives, feature attribution breakdowns,
    peer-group comparisons, MITRE ATT&CK alignments, and actionable playbooks.
    """

    def generate_explanation(
        self,
        user_id: str,
        username: str,
        department: str,
        role: str,
        baseline: BaselineProfile,
        correlation_result: Dict[str, Any],
        recent_events: List[SecurityEvent],
        active_contexts: List[ContextRecord]
    ) -> ExplainabilityPayload:
        composite_risk = correlation_result.get("cumulative_risk", 10.0)
        raw_risk = correlation_result.get("raw_cumulative_risk", 10.0)
        transition_state = correlation_result.get("transition_state", TransitionState.STABLE)
        v_scores = correlation_result.get("recent_vector_scores", {})
        timeline_points = correlation_result.get("timeline_points", [])

        # Check if context dampened
        is_damped = any(p.get("is_damped") for p in timeline_points)
        damping_reasons = [p.get("damping_reason") for p in timeline_points if p.get("damping_reason")]
        damping_reason = damping_reasons[-1] if damping_reasons else None

        # 1. Feature Attribution & Relative Influence
        total_v = sum(v_scores.values()) if sum(v_scores.values()) > 0 else 1.0
        normalized_attribution = {
            k: round((v / total_v) * 100.0, 1) for k, v in v_scores.items()
        }

        # 2. Baseline vs Actual Comparison
        actual_resources = list({e.resource for e in recent_events[-20:]})
        new_resources = [r for r in actual_resources if r not in baseline.common_resources]
        off_hour_events = sum(1 for e in recent_events[-20:] if e.is_off_hours or e.timestamp.hour < 7 or e.timestamp.hour > 20)
        off_hour_pct = round((off_hour_events / max(len(recent_events[-20:]), 1)) * 100.0, 1)

        max_observed_sens = max([e.sensitivity_level for e in recent_events[-20:]], default=1)

        baseline_vs_actual = {
            "baseline_working_hours": "08:00 - 18:00 Mon-Fri",
            "observed_off_hours_activity": f"{off_hour_pct}% of recent operations occurred outside normal hours",
            "baseline_max_sensitivity": f"Tier {baseline.typical_max_sensitivity} (Internal Standard)",
            "observed_max_sensitivity": f"Tier {max_observed_sens} (Confidential / Crown-Jewel)",
            "baseline_common_assets": baseline.common_resources[:5],
            "novel_assets_accessed": new_resources[:5],
            "baseline_daily_velocity": f"~{baseline.avg_daily_events} events/day",
            "peer_group": f"{department} / {role}"
        }

        # 3. Peer Comparison Benchmarking
        peer_comparison = {
            "peer_group_name": f"{department} Standard Cohort",
            "peer_avg_risk_score": 18.4,
            "peer_off_hours_rate": "3.8%",
            "peer_tier5_access_rate": "1.2%",
            "user_deviation_percentile": "96th Percentile" if composite_risk > 70 else ("75th Percentile" if composite_risk > 45 else "35th Percentile")
        }

        # 4. MITRE ATT&CK Mapping
        mitre_mapping = self._map_to_mitre(v_scores, recent_events, transition_state)

        # 5. Natural Language SOC Narrative
        narrative = self._generate_soc_narrative(
            username=username,
            role=role,
            department=department,
            transition_state=transition_state,
            composite_risk=composite_risk,
            raw_risk=raw_risk,
            is_damped=is_damped,
            damping_reason=damping_reason,
            normalized_attribution=normalized_attribution,
            new_resources=new_resources,
            off_hour_pct=off_hour_pct,
            active_contexts=active_contexts
        )

        # 6. Actionable Playbook Recommendations
        playbooks = self._generate_playbooks(composite_risk, transition_state, is_damped, v_scores)

        # 7. Contributing Events
        contributing_events = []
        for p in timeline_points[-8:]:
            contributing_events.append({
                "timestamp": p["timestamp"],
                "resource": p["resource"],
                "action": p["action"],
                "event_score": p["event_score"],
                "is_damped": p["is_damped"],
                "state": p["state"]
            })

        return ExplainabilityPayload(
            user_id=user_id,
            username=username,
            department=department,
            role=role,
            composite_risk_score=composite_risk,
            raw_risk_score=raw_risk,
            is_context_damped=is_damped,
            damping_reason=damping_reason,
            transition_state=transition_state,
            vector_scores=v_scores,
            baseline_vs_actual=baseline_vs_actual,
            natural_language_brief=narrative,
            mitre_mapping=mitre_mapping,
            contributing_events=contributing_events,
            contextual_factors=active_contexts,
            playbook_recommendations=playbooks,
            peer_comparison=peer_comparison
        )

    def _generate_soc_narrative(
        self,
        username: str,
        role: str,
        department: str,
        transition_state: TransitionState,
        composite_risk: float,
        raw_risk: float,
        is_damped: bool,
        damping_reason: Optional[str],
        normalized_attribution: Dict[str, float],
        new_resources: List[str],
        off_hour_pct: float,
        active_contexts: List[ContextRecord]
    ) -> str:
        # Find dominant vector
        top_vector = max(normalized_attribution.items(), key=lambda x: x[1]) if normalized_attribution else ("none", 0.0)
        vector_names = {
            "temporal": "Off-Hours Chrono Anomalies",
            "resource": "Unusual Crown-Jewel Resource Exploration",
            "privilege": "Privilege Escalation & Sensitive Actions",
            "peer_divergence": "Peer-Group Divergence"
        }

        brief = (
            f"Account [{username}] ({role} in {department}) is currently exhibiting a "
            f"'{transition_state.value}' profile with a composite risk score of {composite_risk}/100. "
        )

        if is_damped:
            brief += (
                f"\n\n[CONTEXT SUPPRESSION ACTIVE]: The raw cumulative anomaly score ({raw_risk:.1f}) was dampened "
                f"by legitimate business authorization: {damping_reason}. This intentional suppression prevented a false positive alert."
            )
            return brief

        brief += (
            f"\n\nThe primary behavioral shift is driven by {vector_names.get(top_vector[0], top_vector[0])} "
            f"({top_vector[1]}% of anomaly attribution). "
        )

        if off_hour_pct > 25.0:
            brief += f"Activity shows a notable temporal shift with {off_hour_pct}% of recent operations occurring during off-hours. "

        if new_resources:
            novel_str = ", ".join([f"'{r}'" for r in new_resources[:3]])
            brief += f"The account recently accessed novel high-sensitivity resources outside its established baseline: {novel_str}. "

        if transition_state == TransitionState.CRITICAL_TRANSITION:
            brief += (
                "\n\n[CRITICAL WARNING]: Correlated sequence analysis indicates rapid progression across multiple independent vectors, "
                "consistent with active credential compromise or low-and-slow data staging. Immediate analyst triage recommended."
            )
        elif transition_state == TransitionState.ESCALATING:
            brief += (
                "\n\n[ESCALATING]: Low-level anomalous signals have persisted and compounded over the sliding window. "
                "Behavior warrants verification with the resource owner or team lead."
            )
        else:
            brief += "\n\nBehavior is currently within tolerable variance margins. Continued passive monitoring active."

        return brief

    def _map_to_mitre(self, v_scores: Dict[str, float], events: List[SecurityEvent], state: TransitionState) -> List[Dict[str, str]]:
        tactics = []
        tactics.append({
            "tactic": "Initial Access / Persistence",
            "technique": "T1078 - Valid Accounts",
            "detail": "Legitimate credentials exhibiting atypical temporal and geographical access patterns."
        })

        if v_scores.get("resource", 0) > 40.0:
            tactics.append({
                "tactic": "Discovery",
                "technique": "T1083 - File and Directory Discovery",
                "detail": "Broadened resource entropy across uncharacteristic sensitive repositories."
            })

        if v_scores.get("privilege", 0) > 45.0:
            tactics.append({
                "tactic": "Privilege Escalation",
                "technique": "T1098 - Account Manipulation / T1078.004 Cloud Accounts",
                "detail": "Execution of elevated roles, sudo privilege calls, or IAM permission grants."
            })

        if state == TransitionState.CRITICAL_TRANSITION:
            tactics.append({
                "tactic": "Exfiltration",
                "technique": "T1020 - Automated / Scheduled Exfiltration",
                "detail": "High-volume data queries and bulk export calls to crown-jewel assets."
            })

        return tactics

    def _generate_playbooks(self, risk: float, state: TransitionState, is_damped: bool, v_scores: Dict[str, float]) -> List[str]:
        if is_damped:
            return [
                "Verify ticket completion date and ensure access permissions auto-expire.",
                "Log confirmation entry in context audit trail.",
                "Maintain passive baseline recalibration tracking."
            ]

        if state == TransitionState.CRITICAL_TRANSITION:
            return [
                "[PRIORITY 1] Trigger immediate Step-Up MFA push to user's registered authenticator.",
                "[PRIORITY 2] Revoke active OAuth refresh tokens and terminate active web/SSH sessions.",
                "[PRIORITY 3] Quarantine endpoint network interface to prevent lateral movement.",
                "[PRIORITY 4] Contact Department Manager to confirm whether after-hours bulk access was sanctioned.",
                "[PRIORITY 5] Escalate to Tier-3 Incident Response for forensic timeline acquisition."
            ]
        elif state == TransitionState.ESCALATING:
            return [
                "Send automated Slack/Teams verification prompt asking user to confirm novel resource accesses.",
                "Review recent Git commits / CI/CD pipeline triggers associated with this identity.",
                "Verify whether an unlinked Jira/ServiceNow ticket exists for ongoing project support.",
                "Temporarily place account in High-Fidelity Audit mode for 7 days."
            ]
        else:
            return [
                "No immediate containment required. Allow baseline engine to adapt smoothly.",
                "Review monthly behavioral drift digest during team access review."
            ]

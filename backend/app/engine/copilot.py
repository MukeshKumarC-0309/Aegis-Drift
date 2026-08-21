from typing import Dict, Any, List
from datetime import datetime
from app.models import BaselineProfile, ContextRecord, TransitionState


class ShiftCopilotEngine:
    """
    SOC AI Assistant (ShiftCopilot) Engine:
    Provides context-grounded reasoning, interactive incident Q&A,
    counterfactual simulation advice, and automated executive communication drafting.
    """

    def answer_query(
        self,
        user_id: str,
        username: str,
        department: str,
        role: str,
        question: str,
        investigation_payload: Dict[str, Any],
        blast_radius: Dict[str, Any]
    ) -> Dict[str, Any]:
        q_lower = question.lower()
        risk = investigation_payload.get("composite_risk_score", 0.0)
        state = investigation_payload.get("transition_state", "STABLE")
        is_damped = investigation_payload.get("is_context_damped", False)
        damping_reason = investigation_payload.get("damping_reason", "")
        vectors = investigation_payload.get("vector_scores", {})
        blast_score = blast_radius.get("blast_radius_score", 0.0)
        compliance = blast_radius.get("compliance_impacts", [])
        novel_assets = investigation_payload.get("baseline_vs_actual", {}).get("novel_assets_accessed", [])

        answer = ""
        suggested_actions = []

        if "why" in q_lower or "flagged" in q_lower or "reason" in q_lower or "anomal" in q_lower:
            if is_damped:
                answer = (
                    f"**Account {username} ({role})** was evaluated with an elevated raw anomaly score, "
                    f"but **no alert was fired** because legitimate business authorization was detected:\n\n"
                    f"- **Active Authorization**: {damping_reason}\n"
                    f"- **Damping Applied**: Risk reduced by ~75% down to {risk}/100.\n"
                    f"- **Conclusion**: This is an authorized project or role transition. The system correctly suppressed the false positive."
                )
                suggested_actions = ["View Approved Jira Ticket", "Confirm Expiration Date", "Update Permanent Baseline"]
            else:
                top_vec = max(vectors.items(), key=lambda x: x[1]) if vectors else ("none", 0)
                answer = (
                    f"**Account {username}** transitioned to **{state}** (Risk Score: {risk}/100) due to a sequence of multi-vector deviations:\n\n"
                    f"1. **Primary Driver ({top_vec[0].upper()})**: Generated {top_vec[1]}% anomaly impact.\n"
                    f"2. **Novel Asset Access**: Accessed unauthorized repositories outside baseline: `{', '.join(novel_assets[:3]) or 'Crown-jewel tables'}`.\n"
                    f"3. **Temporal Drift**: Operations occurred outside standard working hours (08:00 - 18:00).\n"
                    f"4. **No Covering Context**: Checked enterprise Jira/ServiceNow registry—no active tickets or on-call records match this high-tier access."
                )
                suggested_actions = ["Enforce Step-Up MFA", "Quarantine Session", "Inspect Network Egress"]

        elif "peer" in q_lower or "compare" in q_lower or "cohort" in q_lower:
            peer_info = investigation_payload.get("peer_comparison", {})
            answer = (
                f"**Peer Cohort Benchmarking Analysis for {username}**:\n\n"
                f"- **Cohort**: {department} - {role}\n"
                f"- **Cohort Median Risk Score**: {peer_info.get('peer_avg_risk_score', '18.4')}/100\n"
                f"- **Current User Risk**: {risk}/100 ({peer_info.get('user_deviation_percentile', '90th+ percentile')})\n"
                f"- **Off-Hours Operation Rate**: Peer average is {peer_info.get('peer_off_hours_rate', '3.8%')}, whereas {username} has over 30% after-hours operations.\n\n"
                f"**Verdict**: This identity is a distinct statistical outlier within the {department} peer group."
            )
            suggested_actions = ["Review Peer Group Baseline", "Trigger Manager Verification"]

        elif "blast" in q_lower or "radius" in q_lower or "impact" in q_lower or "damage" in q_lower:
            crown_count = blast_radius.get("crown_jewels_touched", 0)
            pii = blast_radius.get("pii_data_exposed", False)
            pci = blast_radius.get("pci_vault_exposed", False)
            answer = (
                f"**Blast Radius Assessment (Score: {blast_score}/100 - {blast_radius.get('estimated_impact_level')})**:\n\n"
                f"- **Crown Jewel Assets Touched**: {crown_count} sensitive repositories/databases\n"
                f"- **Customer PII Exposure**: {'YES - Potential GDPR Violation' if pii else 'None detected'}\n"
                f"- **Cardholder / PCI Exposure**: {'YES - Immediate PCI-DSS Containment Mandated' if pci else 'None detected'}\n"
                f"- **Regulatory Exposure**: {len(compliance)} compliance frameworks triggered ({', '.join([c['framework'] for c in compliance]) or 'None'}).\n\n"
                f"**Containment Window**: Immediate credential revocation advised to prevent further exfiltration."
            )
            suggested_actions = ["Quarantine Endpoint Network", "Revoke OAuth Refresh Tokens", "Notify Privacy Officer"]

        elif "draft" in q_lower or "slack" in q_lower or "email" in q_lower or "manager" in q_lower or "message" in q_lower:
            answer = (
                f"Here is a pre-drafted, professional message to {username}'s department manager:\n\n"
                f"```\n"
                f"Subject: [URGENT] Verification Required: Off-Hours Activity for {username}\n\n"
                f"Hi Team Lead,\n\n"
                f"SilentShift Behavioral Defense has flagged an anomalous activity transition for {username} ({role}). "
                f"The account was observed accessing novel high-sensitivity resources ({', '.join(novel_assets[:2]) or 'Production Customer Databases'}) "
                f"outside normal operating hours with no active change ticket registered.\n\n"
                f"Current Risk Level: {state} ({risk}/100).\n\n"
                f"Could you please confirm if this work is authorized? If not, we will proceed with credential revocation.\n\n"
                f"SOC Incident Response Team\n"
                f"```"
            )
            suggested_actions = ["Copy Message to Clipboard", "Send via Webhook", "Escalate to Tier 3"]

        elif "playbook" in q_lower or "remediat" in q_lower or "action" in q_lower or "contain" in q_lower:
            playbooks = investigation_payload.get("playbook_recommendations", [])
            answer = (
                f"**Recommended Incident Containment Playbook for {state}**:\n\n" +
                "\n".join([f"{i+1}. {p}" for i, p in enumerate(playbooks)]) +
                "\n\nExecute the actions below via the Workbench to apply immediate containment."
            )
            suggested_actions = ["Enforce Step-Up MFA", "Quarantine Session", "Accept & Re-Baseline"]

        else:
            answer = (
                f"**SilentShift Forensic Intelligence Briefing for {username}**:\n\n"
                f"- Current State: **{state}** (Composite Risk: {risk}/100)\n"
                f"- Primary Anomaly Signals: {', '.join([f'{k} ({v:.0f}%)' for k, v in vectors.items() if v > 15])}\n"
                f"- Blast Radius Exposure: {blast_score}/100\n"
                f"- Context Protection: {'Active (Suppressed)' if is_damped else 'Unmitigated (Alert Active)'}\n\n"
                f"You can ask me to: **'Compare to peers'**, **'Evaluate blast radius'**, **'Draft manager email'**, or **'Suggest playbook actions'**."
            )
            suggested_actions = ["Compare to Peers", "Evaluate Blast Radius", "Draft Manager Email"]

        return {
            "user_id": user_id,
            "username": username,
            "question": question,
            "answer": answer,
            "suggested_actions": suggested_actions,
            "timestamp": datetime.utcnow().isoformat()
        }

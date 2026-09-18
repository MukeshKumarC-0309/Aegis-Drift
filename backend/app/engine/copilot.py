"""SOC Copilot: a deterministic, grounded question-answering layer.

This is *not* a language model. It is an intent classifier over a fixed question
space, where every answer is composed from values the detection pipeline actually
computed. That constraint is deliberate — an investigation aid must never assert
something it cannot point at evidence for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.core.enums import SENSITIVITY_LABELS


@dataclass(slots=True)
class CopilotAnswer:
    intent: str
    answer: str
    confidence: float
    citations: list[dict] = field(default_factory=list)
    follow_ups: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "intent": self.intent,
            "answer": self.answer,
            "confidence": self.confidence,
            "citations": self.citations,
            "follow_ups": self.follow_ups,
            "data": self.data,
        }


#: intent -> regex patterns. Ordered; the first intent with a match wins, so more
#: specific intents must precede broader ones ("gdpr impact" is compliance, not blast).
INTENT_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("compliance", (r"\b(complian|gdpr|pci|hipaa|soc ?2|iso ?27|regulat|notifiab)",)),
    ("mitre", (r"\b(mitre|att&?ck|technique|tactic|ttp)",)),
    ("why_flagged", (r"\bwhy\b.*\b(flag|alert|risk|score)", r"what.*trigger", r"\breason")),
    ("is_malicious", (r"\b(malicious|real threat|actually bad|false positive|benign)",)),
    ("baseline", (r"\b(baseline|usual|typical|learned profile)", r"\bnormal\b(?!.*\bpeer)")),
    ("timeline", (r"\b(timeline|chronolog|sequence of|when did|first sign)",)),
    ("peer_comparison", (r"\b(peer|colleague|cohort|teammate|compare|percentile)",)),
    ("context_check", (r"\b(ticket|change request|approved|authoris|authoriz|context|justif|on.?call)",)),
    ("recommended_action", (r"\b(what should|recommend|next step|do now|respond|contain|remediat|action)",)),
    ("confidence", (r"\b(confiden|how sure|certain|reliab|how much do you trust)",)),
    ("what_accessed", (r"\b(access|touch|reach|resource|asset)", r"\bwhat data\b")),
    ("blast_radius", (r"\b(blast radius|impact|exposure|how bad|damage|at risk|lateral)",)),
)

SUGGESTED_QUESTIONS: tuple[str, ...] = (
    "Why was this identity flagged?",
    "Is this a real threat or a false positive?",
    "What data could they have reached?",
    "Show me the timeline of the drift.",
    "How does this compare to their peers?",
    "Which MITRE techniques does this map to?",
    "What should I do right now?",
    "Are there approved change tickets covering this?",
    "What regulatory obligations does this trigger?",
    "How confident is the engine in this verdict?",
)


class CopilotEngine:
    """Answers investigation questions from a pre-computed evidence bundle."""

    def answer(self, question: str, bundle: dict[str, Any]) -> CopilotAnswer:
        """``bundle`` carries the explanation, blast radius and correlation summary."""
        intent = self.classify(question)
        handler = getattr(self, f"_answer_{intent}", self._answer_unknown)
        return handler(question, bundle)

    @staticmethod
    def classify(question: str) -> str:
        q = question.lower().strip()
        for intent, patterns in INTENT_PATTERNS:
            if any(re.search(p, q) for p in patterns):
                return intent
        return "unknown"

    # -------------------------------------------------------------- handlers
    def _answer_why_flagged(self, _q: str, b: dict) -> CopilotAnswer:
        explanation = b.get("explanation", {})
        attribution = explanation.get("attribution", [])[:3]
        findings = explanation.get("key_findings", [])[:3]

        lines = [explanation.get("headline", "")]
        if attribution:
            lines.append(
                "\n**Primary drivers:**\n"
                + "\n".join(
                    f"- {a['label']}: {a['score']:.0f}/100 ({a['share']:.0f}% of the verdict)"
                    for a in attribution
                )
            )
        if findings:
            lines.append("\n**Evidence:**\n" + "\n".join(f"- {f['title']} — {f['detail']}" for f in findings))
        return CopilotAnswer(
            intent="why_flagged",
            answer="\n".join(filter(None, lines)),
            confidence=explanation.get("confidence", 70.0),
            citations=self._event_citations(explanation, 4),
            follow_ups=[
                "Is this a real threat or a false positive?",
                "What data could they have reached?",
                "Are there approved change tickets covering this?",
            ],
            data={"attribution": attribution},
        )

    def _answer_is_malicious(self, _q: str, b: dict) -> CopilotAnswer:
        explanation = b.get("explanation", {})
        verdict = explanation.get("verdict", "MONITOR")
        counter = explanation.get("counter_evidence", [])
        confidence = explanation.get("confidence", 60.0)

        stance = {
            "ANTI_TAMPER_OVERRIDE": (
                "**Treat as malicious until disproven.** Audit-evidence destruction was observed. "
                "There is no legitimate workflow in which a user deletes their own audit trail, "
                "and policy blocks any approval from suppressing it."
            ),
            "CONTAINMENT_RECOMMENDED": (
                "**Likely a genuine threat.** The identity crossed the critical threshold with "
                "multiple independent vectors firing simultaneously — a pattern that coincidental "
                "benign behaviour rarely produces."
            ),
            "INVESTIGATE_NOW": (
                "**Unresolved — needs a human decision.** The trajectory is escalating but the "
                "evidence is not yet conclusive. This is precisely the window in which "
                "intervention is cheapest."
            ),
            "SUPPRESSED_BY_CONTEXT": (
                "**Most likely benign.** An approved business context explains the anomalous "
                "activity, and the raw score was damped accordingly."
            ),
            "MONITOR": (
                "**Probably benign, worth watching.** Early drift most often reflects a genuine "
                "role or project change rather than compromise."
            ),
            "NO_ACTION": "**No indication of threat.** Behaviour is within the established envelope.",
        }.get(verdict, "Insufficient signal to characterise this identity.")

        body = [stance, f"\nEngine confidence in this verdict: **{confidence:.0f}%**."]
        if counter:
            body.append("\n**Arguments the other way:**\n" + "\n".join(f"- {c}" for c in counter[:4]))
        return CopilotAnswer(
            intent="is_malicious",
            answer="\n".join(body),
            confidence=confidence,
            citations=self._event_citations(explanation, 3),
            follow_ups=["What should I do right now?", "How does this compare to their peers?"],
            data={"verdict": verdict},
        )

    def _answer_what_accessed(self, _q: str, b: dict) -> CopilotAnswer:
        blast = b.get("blast_radius", {})
        breakdown = blast.get("asset_breakdown", [])[:10]
        if not breakdown:
            return CopilotAnswer("what_accessed", "No asset access recorded in this window.", 90.0)

        rows = "\n".join(
            f"- **{a['name']}** — Tier {a['sensitivity']} "
            f"({SENSITIVITY_LABELS.get(a['sensitivity'], '?')}), {a['category']}"
            + (f", ~{a['records']:,} records" if a["records"] else "")
            + (" — **crown jewel**" if a["crown_jewel"] else "")
            for a in breakdown
        )
        summary = (
            f"{blast.get('assets_touched', 0)} distinct assets were touched, "
            f"{blast.get('crown_jewels_touched', 0)} of them crown jewels."
        )
        return CopilotAnswer(
            intent="what_accessed",
            answer=f"{summary}\n\n{rows}",
            confidence=92.0,
            citations=[{"type": "asset", "label": a["name"], "ref": a["key"]} for a in breakdown[:5]],
            follow_ups=["What is the blast radius?", "What regulatory obligations does this trigger?"],
            data={"assets": breakdown},
        )

    def _answer_blast_radius(self, _q: str, b: dict) -> CopilotAnswer:
        blast = b.get("blast_radius", {})
        reach = blast.get("lateral_reach", {})
        lines = [
            f"**Blast radius score: {blast.get('blast_radius_score', 0):.0f}/100 "
            f"({blast.get('impact_level', 'UNKNOWN')})**",
            "",
            f"- Assets reached: {blast.get('assets_touched', 0)} "
            f"({blast.get('crown_jewels_touched', 0)} crown jewels)",
            f"- Records at risk: ~{blast.get('records_at_risk', 0):,}",
            f"- Modelled financial exposure: {blast.get('estimated_exposure_display', '$0')}",
            f"- PII exposed: {'yes' if blast.get('pii_exposed') else 'no'} · "
            f"Cardholder data: {'yes' if blast.get('cardholder_data_exposed') else 'no'}",
        ]
        if reach:
            lines.append(
                f"- Lateral reach: {reach.get('credential_assets_reached', 0)} credential store(s), "
                f"an estimated {reach.get('estimated_additional_systems', 0)} additional systems"
                + (" — **can escalate to admin**" if reach.get("can_escalate_to_admin") else "")
            )
        lines.append(
            "\nExposure figures are planning estimates from published per-record incident costs, "
            "not a legal determination."
        )
        return CopilotAnswer(
            intent="blast_radius",
            answer="\n".join(lines),
            confidence=80.0,
            follow_ups=["What regulatory obligations does this trigger?", "What should I do right now?"],
            data=blast.get("lateral_reach", {}),
        )

    def _answer_timeline(self, _q: str, b: dict) -> CopilotAnswer:
        explanation = b.get("explanation", {})
        events = sorted(explanation.get("contributing_events", []), key=lambda e: e["timestamp"])[:10]
        if not events:
            return CopilotAnswer("timeline", "No scored events in the current window.", 90.0)

        rows = "\n".join(
            f"- `{e['timestamp'][:16].replace('T', ' ')}` — **{e['action']}** on `{e['resource']}` "
            f"(Tier {e['sensitivity']}, score {e['raw_score']:.0f})"
            + (" · damped" if e["is_damped"] else "")
            + (" · **anti-tamper**" if e.get("anti_tamper") else "")
            for e in events
        )
        return CopilotAnswer(
            intent="timeline",
            answer=f"Chronological sequence of the highest-scoring events:\n\n{rows}",
            confidence=95.0,
            citations=self._event_citations(explanation, 5),
            follow_ups=["Why was this identity flagged?", "Which MITRE techniques does this map to?"],
            data={"events": events},
        )

    def _answer_peer_comparison(self, _q: str, b: dict) -> CopilotAnswer:
        peer = b.get("explanation", {}).get("peer_comparison", {})
        if not peer.get("available"):
            return CopilotAnswer(
                "peer_comparison",
                peer.get("note", "No peer cohort is available for this identity yet."),
                50.0,
            )
        answer = (
            f"Cohort **{peer['cohort']}** has {peer['member_count']} members with a mean risk of "
            f"{peer['cohort_mean_risk']:.1f} (σ = {peer['cohort_stddev']:.1f}).\n\n"
            f"This identity scores **{peer['identity_risk']:.1f}** — a z-score of "
            f"**{peer['z_score']:+.2f}**, placing them at the **{peer['percentile']}th percentile**.\n\n"
            f"{peer['interpretation']}"
        )
        return CopilotAnswer(
            "peer_comparison",
            answer,
            85.0,
            follow_ups=["Why was this identity flagged?", "What is their normal baseline?"],
            data=peer,
        )

    def _answer_recommended_action(self, _q: str, b: dict) -> CopilotAnswer:
        actions = b.get("explanation", {}).get("recommended_actions", [])
        if not actions:
            return CopilotAnswer(
                "recommended_action", "No action required — behaviour is within baseline.", 88.0
            )
        rows = "\n".join(
            f"{i}. **{a['label']}** _({a['urgency']})_ — {a['rationale']}" for i, a in enumerate(actions, 1)
        )
        return CopilotAnswer(
            "recommended_action",
            f"Recommended response, in priority order:\n\n{rows}\n\n"
            "Each of these can be executed from the Response tab, and every execution is "
            "written to the immutable audit log.",
            88.0,
            follow_ups=["Is this a real threat or a false positive?", "What is the blast radius?"],
            data={"actions": actions},
        )

    def _answer_context_check(self, _q: str, b: dict) -> CopilotAnswer:
        contexts = b.get("explanation", {}).get("context_factors", [])
        if not contexts:
            return CopilotAnswer(
                "context_check",
                "**No context records exist for this identity.** Nothing authorises the observed "
                "activity — there is no approved change ticket, on-call rotation or role transfer "
                "covering this window.",
                92.0,
                follow_ups=["What should I do right now?"],
            )
        rows = "\n".join(
            f"- **{c['type']}** `{c['ticket'] or c['id']}` — {c['title']}\n"
            f"  Approved by {c['approved_by']}, valid {c['valid_from'][:10]} → {c['valid_until'][:10]}, "
            f"damping ×{c['damping_factor']:.2f}"
            + ("  _(currently active)_" if c["active"] else "  _(window lapsed)_")
            for c in contexts
        )
        active = sum(1 for c in contexts if c["active"])
        return CopilotAnswer(
            "context_check",
            f"{len(contexts)} context record(s), {active} currently active:\n\n{rows}",
            90.0,
            data={"contexts": contexts},
            follow_ups=["Is this a real threat or a false positive?"],
        )

    def _answer_mitre(self, _q: str, b: dict) -> CopilotAnswer:
        techniques = b.get("explanation", {}).get("mitre_techniques", [])
        if not techniques:
            return CopilotAnswer("mitre", "No ATT&CK techniques were evidenced in this window.", 85.0)
        rows = "\n".join(
            f"- **{t['id']} — {t['name']}** ({t['tactic']}, {t['confidence']}% confidence)\n"
            f"  {t['description']}"
            for t in techniques[:8]
        )
        tactics = sorted({t["tactic"] for t in techniques})
        return CopilotAnswer(
            "mitre",
            f"{len(techniques)} technique(s) evidenced across {len(tactics)} tactic(s) "
            f"({', '.join(tactics)}):\n\n{rows}",
            82.0,
            data={"techniques": techniques},
            follow_ups=["Show me the timeline of the drift.", "What should I do right now?"],
        )

    def _answer_compliance(self, _q: str, b: dict) -> CopilotAnswer:
        impacts = b.get("blast_radius", {}).get("compliance_impacts", [])
        if not impacts:
            return CopilotAnswer(
                "compliance",
                "No regulatory thresholds were crossed — the assets touched carry no declared "
                "PII, cardholder or health-data scope.",
                85.0,
            )
        rows = "\n".join(
            f"- **{i['framework']}** ({i['severity']}) — {i['obligation']}\n"
            f"  In scope: {', '.join(i['in_scope_assets']) or 'n/a'}"
            for i in impacts
        )
        return CopilotAnswer(
            "compliance",
            f"{len(impacts)} regulatory framework(s) are implicated:\n\n{rows}\n\n"
            "This is an engineering assessment to route the question, not legal advice — "
            "confirm notification obligations with counsel.",
            78.0,
            data={"impacts": impacts},
            follow_ups=["What is the blast radius?"],
        )

    def _answer_baseline(self, _q: str, b: dict) -> CopilotAnswer:
        comparison = b.get("explanation", {}).get("baseline_comparison", {})
        if not comparison:
            return CopilotAnswer("baseline", "No baseline has been established yet.", 60.0)
        off = comparison.get("off_hours", {})
        sens = comparison.get("max_sensitivity", {})
        daily = comparison.get("daily_events", {})
        answer = (
            f"**Learned profile** (from {comparison.get('baseline_sample_size', 0)} events, "
            f"{comparison.get('baseline_maturity', 0):.0%} maturity):\n\n"
            f"- Circadian rhythm: {comparison.get('circadian_profile', 'unknown')}\n"
            f"- Off-hours activity: {off.get('baseline', 0)}% normally → "
            f"**{off.get('observed', 0)}% observed**\n"
            f"- Sensitivity ceiling: Tier {sens.get('baseline')} ({sens.get('baseline_label')}) → "
            f"**Tier {sens.get('observed')} ({sens.get('observed_label')}) observed**\n"
            f"- Daily volume: {daily.get('baseline', 0)} ± {daily.get('stddev', 0)} events → "
            f"**{daily.get('observed', 0)} observed**\n"
            f"- Routine resources: {', '.join(comparison.get('known_resources', [])[:5]) or 'none'}\n"
            f"- Novel this window: {', '.join(comparison.get('novel_resources', [])[:5]) or 'none'}"
        )
        return CopilotAnswer(
            "baseline",
            answer,
            90.0,
            data=comparison,
            follow_ups=["Why was this identity flagged?", "How does this compare to their peers?"],
        )

    def _answer_confidence(self, _q: str, b: dict) -> CopilotAnswer:
        explanation = b.get("explanation", {})
        confidence = explanation.get("confidence", 50.0)
        counter = explanation.get("counter_evidence", [])
        maturity = explanation.get("baseline_comparison", {}).get("baseline_maturity", 0)
        answer = (
            f"Engine confidence in this verdict: **{confidence:.0f}%**.\n\n"
            f"Confidence rises with baseline maturity (currently {maturity:.0%}), the number of "
            "independently corroborating events, and how many vectors fire at once. It is "
            "reduced by each argument against the verdict."
        )
        if counter:
            answer += "\n\n**Reducing confidence:**\n" + "\n".join(f"- {c}" for c in counter)
        return CopilotAnswer("confidence", answer, confidence, data={"counter_evidence": counter})

    def _answer_unknown(self, question: str, b: dict) -> CopilotAnswer:
        explanation = b.get("explanation", {})
        return CopilotAnswer(
            intent="unknown",
            answer=(
                f'I could not map "{question}" to a question I can answer from the evidence '
                "on hand. I answer only from what the detection pipeline actually computed, so "
                "I would rather say so than speculate.\n\n"
                f"Current state: {explanation.get('headline', 'no assessment available')}\n\n"
                "**Try one of these:**\n" + "\n".join(f"- {q}" for q in SUGGESTED_QUESTIONS[:6])
            ),
            confidence=20.0,
            follow_ups=list(SUGGESTED_QUESTIONS[:4]),
        )

    @staticmethod
    def _event_citations(explanation: dict, limit: int) -> list[dict]:
        return [
            {
                "type": "event",
                "label": f"{e['action']} on {e['resource']}",
                "ref": e["event_id"],
                "timestamp": e["timestamp"],
                "score": e["raw_score"],
            }
            for e in explanation.get("contributing_events", [])[:limit]
        ]

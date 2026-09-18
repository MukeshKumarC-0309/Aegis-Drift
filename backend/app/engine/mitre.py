"""MITRE ATT&CK mapping for observed behaviour.

Holds a curated subset of the Enterprise matrix relevant to identity threats, plus
the heuristics that map scored events and risk vectors onto techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.enums import ANTI_TAMPER_ACTIONS, RiskVector
from app.engine.types import ScoredEvent


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactic: str
    description: str
    detection_hint: str = ""


TACTIC_ORDER: tuple[str, ...] = (
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

CATALOG: dict[str, Technique] = {
    t.id: t
    for t in (
        Technique(
            "T1078",
            "Valid Accounts",
            "Initial Access",
            "Adversaries use legitimate credentials to blend into normal operations.",
            "Authentication from an unfamiliar network origin or at an unusual hour.",
        ),
        Technique(
            "T1078.004",
            "Valid Accounts: Cloud Accounts",
            "Initial Access",
            "Compromised cloud identities used against the control plane.",
            "Console or API authentication outside the identity's known ASN set.",
        ),
        Technique(
            "T1098",
            "Account Manipulation",
            "Persistence",
            "Modifying accounts or their permissions to retain access.",
            "IAM policy attachment, role binding or access-key creation.",
        ),
        Technique(
            "T1136",
            "Create Account",
            "Persistence",
            "Creating an account to maintain a foothold.",
            "New principal created outside the joiner-mover-leaver workflow.",
        ),
        Technique(
            "T1548",
            "Abuse Elevation Control Mechanism",
            "Privilege Escalation",
            "Bypassing controls that gate elevated permissions.",
            "sudo or role assumption by an identity that rarely elevates.",
        ),
        Technique(
            "T1484",
            "Domain or Tenant Policy Modification",
            "Privilege Escalation",
            "Altering directory or tenant policy to widen access.",
            "Directory policy change from a non-administrative baseline.",
        ),
        Technique(
            "T1562",
            "Impair Defenses",
            "Defense Evasion",
            "Disabling or degrading security controls and telemetry.",
            "Logging disabled, MFA turned off, or detection rules altered.",
        ),
        Technique(
            "T1562.008",
            "Impair Defenses: Disable Cloud Logs",
            "Defense Evasion",
            "Deleting or halting cloud audit trails to destroy evidence.",
            "CloudTrail / audit-log deletion — never contextually justifiable.",
        ),
        Technique(
            "T1070",
            "Indicator Removal",
            "Defense Evasion",
            "Deleting artefacts that would reveal the intrusion.",
            "Audit-log or history deletion following privileged activity.",
        ),
        Technique(
            "T1110",
            "Brute Force",
            "Credential Access",
            "Repeated authentication attempts to guess credentials.",
            "A burst of DENIED authentication outcomes.",
        ),
        Technique(
            "T1555",
            "Credentials from Password Stores",
            "Credential Access",
            "Harvesting secrets from vaults and secret managers.",
            "Secret-manager reads outside the identity's normal surface.",
        ),
        Technique(
            "T1552",
            "Unsecured Credentials",
            "Credential Access",
            "Locating credentials left in files, config or code.",
            "Access to key material or config stores by a non-owner.",
        ),
        Technique(
            "T1087",
            "Account Discovery",
            "Discovery",
            "Enumerating accounts and their privileges.",
            "Directory or IAM listing well above the baseline rate.",
        ),
        Technique(
            "T1213",
            "Data from Information Repositories",
            "Collection",
            "Mining wikis, ticketing and documentation for valuable data.",
            "Schema or documentation reads immediately preceding data access.",
        ),
        Technique(
            "T1530",
            "Data from Cloud Storage",
            "Collection",
            "Accessing objects in cloud storage buckets.",
            "Bulk object reads from a bucket the identity has never touched.",
        ),
        Technique(
            "T1005",
            "Data from Local System",
            "Collection",
            "Collecting data from systems the identity already reaches.",
            "Sustained high-sensitivity reads with rising volume.",
        ),
        Technique(
            "T1021",
            "Remote Services",
            "Lateral Movement",
            "Pivoting between systems using valid credentials.",
            "Bastion or cross-account role usage outside the norm.",
        ),
        Technique(
            "T1567",
            "Exfiltration Over Web Service",
            "Exfiltration",
            "Sending data out through a permitted web service.",
            "Large egress to an external destination.",
        ),
        Technique(
            "T1048",
            "Exfiltration Over Alternative Protocol",
            "Exfiltration",
            "Moving data out over a channel other than the C2 path.",
            "Egress volume several standard deviations above baseline.",
        ),
        Technique(
            "T1020",
            "Automated Exfiltration",
            "Exfiltration",
            "Scripted bulk extraction of collected data.",
            "A bulk export action with a very high record count.",
        ),
        Technique(
            "T1531",
            "Account Access Removal",
            "Impact",
            "Locking legitimate users out to hinder response.",
            "Mass disable or password reset of other principals.",
        ),
        Technique(
            "T1485",
            "Data Destruction",
            "Impact",
            "Irrecoverably destroying data or backups.",
            "Delete actions against production data stores.",
        ),
    )
}

#: Direct action -> technique shortcuts, checked before the heuristics.
ACTION_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "delete_audit_logs": ("T1562.008", "T1070"),
    "disable_logging": ("T1562", "T1562.008"),
    "disable_mfa": ("T1562", "T1098"),
    "dump_credentials": ("T1555", "T1552"),
    "create_backdoor_user": ("T1136", "T1098"),
    "rotate_root_key": ("T1098", "T1548"),
    "iam_modify": ("T1098", "T1484"),
    "attach_policy": ("T1098",),
    "grant_permission": ("T1098",),
    "create_access_key": ("T1098", "T1552"),
    "assume_role": ("T1548", "T1021"),
    "sudo": ("T1548",),
    "export_all": ("T1020", "T1048"),
    "export": ("T1567",),
    "query_bulk": ("T1005", "T1213"),
    "login": ("T1078",),
}


@dataclass(slots=True)
class TechniqueHit:
    technique: Technique
    confidence: int
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.technique.id,
            "name": self.technique.name,
            "tactic": self.technique.tactic,
            "description": self.technique.description,
            "detection_hint": self.technique.detection_hint,
            "confidence": self.confidence,
            "evidence": self.evidence[:4],
        }


def map_techniques(
    scored_events: list[ScoredEvent],
    vector_scores: dict[str, float],
) -> list[dict]:
    """Derive the ATT&CK techniques evidenced by a scored event stream."""
    hits: dict[str, TechniqueHit] = {}

    def add(tid: str, confidence: int, evidence: str) -> None:
        technique = CATALOG.get(tid)
        if not technique:
            return
        existing = hits.get(tid)
        if existing:
            existing.confidence = max(existing.confidence, confidence)
            if evidence not in existing.evidence:
                existing.evidence.append(evidence)
        else:
            hits[tid] = TechniqueHit(technique, confidence, [evidence])

    denied_auths = 0
    for scored in scored_events:
        event = scored.event
        if scored.raw_score < 30 and event.action_key not in ANTI_TAMPER_ACTIONS:
            continue

        evidence = f"{event.occurred_at:%Y-%m-%d %H:%M} — {event.action} on {event.resource}"
        confidence = int(min(98, 45 + scored.raw_score * 0.5))

        for tid in ACTION_TECHNIQUES.get(event.action_key, ()):
            add(tid, confidence, evidence)

        if event.event_type.value == "AUTHENTICATION":
            if event.outcome.upper() in {"DENIED", "FAILURE"}:
                denied_auths += 1
            if scored.vector_scores.get(RiskVector.GEOVELOCITY.value, 0) >= 55:
                add("T1078.004", confidence, evidence)
        if event.sensitivity_level >= 4 and event.record_count > 5000:
            add(
                "T1530" if "s3" in event.resource or "bucket" in event.resource else "T1005",
                confidence,
                evidence,
            )
        if event.bytes_transferred > 50_000_000:
            add("T1048", confidence, evidence)
        if "schema" in event.resource.lower() or "doc" in event.resource.lower():
            add("T1213", max(50, confidence - 15), evidence)
        if "secret" in event.resource.lower() or "vault" in event.resource.lower():
            add("T1555", confidence, evidence)

    if denied_auths >= 5:
        add("T1110", 70, f"{denied_auths} denied authentication attempts in the window")

    # Vector-level signals that no single event fully expresses.
    if vector_scores.get(RiskVector.GEOVELOCITY.value, 0) >= 70:
        add("T1078", 72, "Authentication origin inconsistent with established geography")
    if vector_scores.get(RiskVector.PRIVILEGE.value, 0) >= 70:
        add("T1548", 70, "Sustained privileged-action rate above baseline")
    if vector_scores.get(RiskVector.VOLUME.value, 0) >= 70:
        add("T1020", 74, "Egress volume several standard deviations above baseline")

    ordered = sorted(
        hits.values(),
        key=lambda h: (TACTIC_ORDER.index(h.technique.tactic), -h.confidence),
    )
    return [h.as_dict() for h in ordered]


def coverage_matrix(all_technique_ids: set[str]) -> list[dict]:
    """Tactic-by-tactic coverage view for the ATT&CK heat map."""
    matrix: list[dict] = []
    for tactic in TACTIC_ORDER:
        techniques = [t for t in CATALOG.values() if t.tactic == tactic]
        observed = [t for t in techniques if t.id in all_technique_ids]
        matrix.append(
            {
                "tactic": tactic,
                "total": len(techniques),
                "observed": len(observed),
                "techniques": [
                    {
                        "id": t.id,
                        "name": t.name,
                        "observed": t.id in all_technique_ids,
                        "description": t.description,
                    }
                    for t in techniques
                ],
            }
        )
    return matrix

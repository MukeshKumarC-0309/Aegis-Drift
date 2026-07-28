from typing import List, Dict, Optional, Tuple
from datetime import datetime
from app.models import SecurityEvent, ContextRecord


class ContextAwareEngine:
    """
    Context-Aware Damping & False Positive Suppression Engine:
    Validates anomalous activities against legitimate business contexts:
    - Approved change management tickets (e.g. ServiceNow, Jira)
    - Role / Department transfers & onboarding transitions
    - Scheduled maintenance windows
    - On-call rotations & emergency escalation duty
    - Approved travel or remote work exemptions
    """

    def __init__(self):
        self.context_records: Dict[str, List[ContextRecord]] = {}

    def register_context(self, record: ContextRecord):
        if record.user_id not in self.context_records:
            self.context_records[record.user_id] = []
        self.context_records[record.user_id].append(record)

    def get_user_contexts(self, user_id: str) -> List[ContextRecord]:
        return self.context_records.get(user_id, [])

    def evaluate_context(self, event: SecurityEvent, raw_risk_score: float) -> Tuple[float, bool, Optional[str], Optional[ContextRecord]]:
        """
        Determines if an event matches an active legitimate context.
        Only dampens if:
        1. Context window is currently active.
        2. AND either:
           - The resource matches target_resources defined in the ticket
           - OR an explicit event context tag matches the ticket reference
           - OR target_resources was empty (broad department role reassignment)
        Crucially, malicious out-of-scope actions (e.g., deleting audit logs, tampering with IAM)
        are NOT damped even if an on-call rotation exists.
        """
        records = self.context_records.get(event.user_id, [])

        # Check explicit event tags first
        for tag in event.context_tags:
            if tag.startswith("ticket:") or tag.startswith("jira:"):
                damping_factor = 0.35
                damped_score = max(5.0, raw_risk_score * damping_factor)
                return damped_score, True, f"Damped by verified event authorization tag: {tag}", None

        if not records:
            return raw_risk_score, False, None, None

        ev_time = event.timestamp
        for rec in records:
            if not rec.active:
                continue

            # Check validity window
            if rec.valid_from <= ev_time <= rec.valid_until:
                # Disallow damping for blatant destructive/tampering actions regardless of context
                if event.action in ["delete_audit_logs", "dump_credentials"]:
                    continue

                # Check if resource matches the scoped target resources
                resource_matches = False
                if not rec.target_resources:
                    # Broad project transfer without asset lock
                    resource_matches = True
                else:
                    for tgt in rec.target_resources:
                        if tgt.lower() in event.resource.lower() or event.resource.lower() in tgt.lower():
                            resource_matches = True
                            break

                tag_matches = rec.ticket_reference and any(rec.ticket_reference.lower() in t.lower() for t in event.context_tags)

                if resource_matches or tag_matches:
                    damped_score = max(5.0, raw_risk_score * rec.damping_factor)
                    reason = (
                        f"Risk score damped from {raw_risk_score:.1f} to {damped_score:.1f} via "
                        f"{rec.context_type} [{rec.ticket_reference or rec.id}]: '{rec.description}' "
                        f"(Approved by {rec.approved_by})"
                    )
                    return round(damped_score, 1), True, reason, rec

        return raw_risk_score, False, None, None

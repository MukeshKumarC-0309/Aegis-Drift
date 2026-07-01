import math
from typing import List, Dict, Any, Tuple
from collections import Counter
from datetime import datetime
from app.models import SecurityEvent, BaselineProfile


class BaselineEngine:
    """
    Computes and maintains multi-signal behavioral baselines:
    1. Circadian / Temporal Profile (circadian kernel density over 24 hours & days of week)
    2. Resource Distribution & Shannon Access Entropy
    3. Action & Privilege Sensitivity Distribution
    4. Peer-Group Homology & Centroids
    """

    def __init__(self):
        # Cache of peer-group baseline metrics
        self.peer_groups: Dict[str, Dict[str, Any]] = {}

    def build_baseline_profile(self, user_id: str, username: str, department: str, role: str, historical_events: List[SecurityEvent]) -> BaselineProfile:
        if not historical_events:
            # Default uniform baseline
            hourly = {h: 1.0 / 24.0 for h in range(24)}
            dow = {d: 1.0 / 7.0 for d in range(7)}
            return BaselineProfile(
                user_id=user_id,
                username=username,
                department=department,
                role=role,
                hourly_distribution=hourly,
                day_of_week_distribution=dow,
                common_resources=[],
                resource_categories={},
                typical_resource_entropy=0.5,
                avg_daily_events=20.0,
                typical_max_sensitivity=2,
                peer_group_id=f"{department}_{role}".lower().replace(" ", "_"),
                last_updated=datetime.utcnow()
            )

        # 1. Hourly distribution with Laplacian smoothing
        hours = [ev.timestamp.hour for ev in historical_events]
        hour_counts = Counter(hours)
        total_events = len(historical_events)
        alpha = 0.5  # smoothing factor
        hourly = {h: (hour_counts.get(h, 0) + alpha) / (total_events + 24 * alpha) for h in range(24)}

        # 2. Day of week distribution
        dows = [ev.timestamp.weekday() for ev in historical_events]
        dow_counts = Counter(dows)
        dow = {d: (dow_counts.get(d, 0) + alpha) / (total_events + 7 * alpha) for d in range(7)}

        # 3. Resource frequency and Shannon entropy
        resources = [ev.resource for ev in historical_events]
        resource_counts = Counter(resources)
        total_res = len(resources)
        entropy = 0.0
        for count in resource_counts.values():
            p = count / total_res
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize entropy by log2(N) if N > 1
        num_unique = len(resource_counts)
        norm_entropy = (entropy / math.log2(num_unique)) if num_unique > 1 else 0.2

        # 4. Sensitivity metrics
        sensitivities = [ev.sensitivity_level for ev in historical_events]
        typical_max_sens = max(sensitivities) if sensitivities else 2

        # 5. Daily event volume
        dates = {ev.timestamp.date() for ev in historical_events}
        num_days = max(len(dates), 1)
        avg_daily = total_events / num_days

        common_res = [res for res, _ in resource_counts.most_common(15)]

        profile = BaselineProfile(
            user_id=user_id,
            username=username,
            department=department,
            role=role,
            hourly_distribution=hourly,
            day_of_week_distribution=dow,
            common_resources=common_res,
            resource_categories=dict(resource_counts.most_common(8)),
            typical_resource_entropy=round(norm_entropy, 3),
            avg_daily_events=round(avg_daily, 1),
            typical_max_sensitivity=typical_max_sens,
            peer_group_id=f"{department}_{role}".lower().replace(" ", "_"),
            last_updated=datetime.utcnow()
        )
        return profile

    def evaluate_event_anomaly(self, event: SecurityEvent, baseline: BaselineProfile) -> Dict[str, float]:
        """
        Evaluates a single event across 4 distinct behavioral vectors.
        Returns a dict of normalized anomaly scores [0 - 100].
        """
        # A. Temporal anomaly
        hour = event.timestamp.hour
        weekday = event.timestamp.weekday()
        prob_hour = baseline.hourly_distribution.get(hour, 1.0 / 24.0)
        prob_dow = baseline.day_of_week_distribution.get(weekday, 1.0 / 7.0)

        # In typical 9-5 work, off-hour prob is ~0.005, working hours is ~0.10
        # Lower probability => higher anomaly
        hour_anomaly = max(0.0, 1.0 - (prob_hour * 12.0))  # scaled
        if event.is_off_hours:
            hour_anomaly = max(hour_anomaly, 0.75)
        if weekday >= 5 and prob_dow < 0.08:  # weekend activity if normally inactive
            hour_anomaly = max(hour_anomaly, 0.7)
        temporal_score = min(100.0, hour_anomaly * 100.0)

        # B. Resource divergence & sensitivity jump
        is_known_resource = event.resource in baseline.common_resources
        resource_anomaly = 15.0 if is_known_resource else 65.0

        sens_diff = event.sensitivity_level - baseline.typical_max_sensitivity
        if sens_diff > 0:
            # Escalated sensitivity access
            sensitivity_score = min(100.0, 40.0 + (sens_diff * 25.0))
        else:
            sensitivity_score = 10.0

        resource_vector_score = min(100.0, (resource_anomaly * 0.4) + (sensitivity_score * 0.6))

        # C. Privilege & Action vector
        action_lower = event.action.lower()
        if action_lower in ["sudo", "assume_role", "iam_modify", "export_all", "dump_credentials", "delete_audit_logs"]:
            privilege_score = 90.0 if baseline.typical_max_sensitivity < 4 else 45.0
        elif action_lower in ["write", "delete", "export", "query_bulk"]:
            privilege_score = 50.0
        else:
            privilege_score = 15.0

        # D. Peer Group Divergence
        peer_score = self._compute_peer_divergence(event, baseline)

        return {
            "temporal": round(temporal_score, 2),
            "resource": round(resource_vector_score, 2),
            "privilege": round(privilege_score, 2),
            "peer_divergence": round(peer_score, 2)
        }

    def _compute_peer_divergence(self, event: SecurityEvent, baseline: BaselineProfile) -> float:
        """
        Compares event characteristics against role/department norms.
        """
        # Engineers usually don't query HR/Payroll or Crown-Jewel Financials
        dept = baseline.department.lower()
        res = event.resource.lower()
        act = event.action.lower()

        divergence = 20.0  # nominal baseline

        if "engineer" in dept or "dev" in dept:
            if any(k in res for k in ["payroll", "salary", "financial_ledger", "exec_briefings", "customer_credit_cards"]):
                divergence += 65.0
            if "iam_modify" in act or "assume_role" in act and "devops" not in baseline.role.lower():
                divergence += 45.0
        elif "finance" in dept:
            if any(k in res for k in ["github_private", "kubernetes_prod", "core_backend_repo", "prod_ssh_keys"]):
                divergence += 70.0
        elif "hr" in dept:
            if any(k in res for k in ["prod_database", "api_gateway", "aws_root_keys"]):
                divergence += 75.0

        return min(100.0, divergence)

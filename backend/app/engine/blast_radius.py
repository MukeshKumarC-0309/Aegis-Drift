from typing import List, Dict, Any
from app.models import SecurityEvent, BaselineProfile, TransitionState


class BlastRadiusEngine:
    """
    Calculates entity relationships, blast radius, and downstream compliance impact
    for any monitored identity based on accessed resources, privilege reach,
    and crown-jewel dependencies.
    """

    def compute_blast_radius(
        self,
        user_id: str,
        username: str,
        department: str,
        role: str,
        recent_events: List[SecurityEvent],
        baseline: BaselineProfile,
        composite_risk: float
    ) -> Dict[str, Any]:
        # Catalog of enterprise assets with metadata
        asset_catalog = {
            "prod_customer_sql_replica": {"type": "Database", "sensitivity": 4, "pii": True, "pci": False, "records": "1.2M Customers"},
            "prod_payment_vault_metadata": {"type": "Payment Vault", "sensitivity": 4, "pii": True, "pci": True, "records": "340K Cards"},
            "crown_jewel_customer_pii_export.tar.gz": {"type": "Data Egress", "sensitivity": 5, "pii": True, "pci": True, "records": "2.5M Profiles"},
            "internal_schema_docs_customer_pii": {"type": "Documentation", "sensitivity": 3, "pii": False, "pci": False, "records": "Schema Metadata"},
            "aws_iam_policy_admin_attach": {"type": "Cloud IAM", "sensitivity": 5, "pii": False, "pci": False, "records": "Root Privileges"},
            "cloudtrail_audit_log_stream": {"type": "Audit Trail", "sensitivity": 5, "pii": False, "pci": False, "records": "SIEM Telemetry"},
            "iam_role_security_auditor": {"type": "Cloud Role", "sensitivity": 4, "pii": False, "pci": False, "records": "Read All Accounts"},
            "aws_management_console": {"type": "Control Plane", "sensitivity": 3, "pii": False, "pci": False, "records": "Console Access"},
            "prod_datalake_s3": {"type": "Data Lake", "sensitivity": 4, "pii": True, "pci": False, "records": "8.4M Analytical Rows"},
            "snowflake_titan_lake": {"type": "Data Warehouse", "sensitivity": 4, "pii": True, "pci": False, "records": "Core Business Metrics"},
            "customer_analytics_warehouse": {"type": "Data Warehouse", "sensitivity": 4, "pii": True, "pci": False, "records": "User Telemetry"},
            "gcp_resourcemanager_organization_admin": {"type": "Org IAM", "sensitivity": 5, "pii": False, "pci": False, "records": "Entire Cloud Org"},
            "gcp_secret_manager_db_keys": {"type": "Secret Store", "sensitivity": 4, "pii": False, "pci": True, "records": "Prod DB Passwords"},
            "gcp_iam_service_account_token": {"type": "Service Token", "sensitivity": 3, "pii": False, "pci": False, "records": "API Credentials"},
            "github_repo_webapp": {"type": "Source Code", "sensitivity": 1, "pii": False, "pci": False, "records": "Frontend Repository"},
            "kubernetes_cluster_dev": {"type": "Container Cluster", "sensitivity": 2, "pii": False, "pci": False, "records": "Dev Namespaces"},
            "sso_okta_gateway": {"type": "IDP Gateway", "sensitivity": 2, "pii": False, "pci": False, "records": "SSO Sessions"}
        }

        # Identify all resources accessed recently
        accessed_res = {ev.resource: ev for ev in recent_events[-20:]}
        
        nodes = []
        links = []

        # Central User Node
        nodes.append({
            "id": user_id,
            "label": username,
            "type": "Identity",
            "tier": 1,
            "risk_score": composite_risk,
            "is_center": True,
            "status": "COMPROMISED" if composite_risk >= 70 else ("ELEVATED" if composite_risk >= 35 else "STABLE")
        })

        pii_exposed = False
        pci_exposed = False
        crown_jewel_count = 0
        total_estimated_records = 0

        for res_name, ev in accessed_res.items():
            meta = asset_catalog.get(res_name, {"type": "System", "sensitivity": ev.sensitivity_level, "pii": False, "pci": False, "records": "N/A"})
            sens = meta.get("sensitivity", ev.sensitivity_level)
            is_anomalous = res_name not in baseline.common_resources or sens >= 4

            if meta.get("pii"):
                pii_exposed = True
            if meta.get("pci"):
                pci_exposed = True
            if sens >= 4:
                crown_jewel_count += 1

            node_id = f"res_{res_name}"
            nodes.append({
                "id": node_id,
                "label": res_name,
                "type": meta["type"],
                "tier": sens,
                "records": meta.get("records", "Standard"),
                "is_anomalous": is_anomalous,
                "status": "ANOMALOUS_TOUCH" if is_anomalous else "BASELINE_TOUCH"
            })

            links.append({
                "source": user_id,
                "target": node_id,
                "action": ev.action,
                "is_anomalous": is_anomalous,
                "sensitivity": sens
            })

        # Calculate blast radius metric (0-100)
        blast_score = min(100.0, round((composite_risk * 0.4) + (crown_jewel_count * 15.0) + (20.0 if pci_exposed else 0.0) + (15.0 if pii_exposed else 0.0), 1))

        compliance_violations = []
        if pii_exposed and composite_risk >= 50:
            compliance_violations.append({
                "framework": "GDPR Art. 32 / 33",
                "risk": "Unauthorized Access to Customer Personal Data",
                "severity": "CRITICAL" if composite_risk >= 75 else "HIGH",
                "mandatory_notification": "72-hour DPA notification trigger potential"
            })
        if pci_exposed and composite_risk >= 50:
            compliance_violations.append({
                "framework": "PCI-DSS v4.0 Req. 7 & 10",
                "risk": "Payment Cardholder Environment Exposure",
                "severity": "CRITICAL",
                "mandatory_notification": "Acquiring bank notification required"
            })
        if crown_jewel_count >= 2:
            compliance_violations.append({
                "framework": "SOC 2 Type II (Trust Services Criteria CC6.1)",
                "risk": "Deficiency in Logical Access Separation of Duties",
                "severity": "MEDIUM",
                "mandatory_notification": "Internal audit review required"
            })

        return {
            "blast_radius_score": blast_score,
            "crown_jewels_touched": crown_jewel_count,
            "pii_data_exposed": pii_exposed,
            "pci_vault_exposed": pci_exposed,
            "estimated_impact_level": "CATASTROPHIC" if blast_score >= 80 else ("HIGH" if blast_score >= 50 else "MODERATE"),
            "compliance_impacts": compliance_violations,
            "graph": {
                "nodes": nodes,
                "links": links
            }
        }

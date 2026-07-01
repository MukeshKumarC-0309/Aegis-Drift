from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class EventType(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    FILE_ACCESS = "FILE_ACCESS"
    PRIVILEGE_ACTION = "PRIVILEGE_ACTION"
    API_CALL = "API_CALL"
    NETWORK_EGRESS = "NETWORK_EGRESS"
    ROLE_MODIFICATION = "ROLE_MODIFICATION"


class TransitionState(str, Enum):
    STABLE = "STABLE"
    EARLY_DRIFT = "EARLY_DRIFT"
    ESCALATING = "ESCALATING"
    CRITICAL_TRANSITION = "CRITICAL_TRANSITION"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEvent(BaseModel):
    id: str
    timestamp: datetime
    user_id: str
    username: str
    department: str
    role: str
    event_type: EventType
    resource: str
    sensitivity_level: int = Field(default=1, ge=1, le=5)  # 1 (public) to 5 (crown-jewel / prod keys)
    action: str  # read, write, delete, sudo, assume_role, export, query
    ip_address: str = "10.0.0.1"
    is_off_hours: bool = False
    context_tags: List[str] = []
    metadata: Dict[str, Any] = {}


class BaselineProfile(BaseModel):
    user_id: str
    username: str
    department: str
    role: str
    hourly_distribution: Dict[int, float] = {}  # 0-23 probability
    day_of_week_distribution: Dict[int, float] = {}  # 0-6 probability
    common_resources: List[str] = []
    resource_categories: Dict[str, float] = {}
    typical_resource_entropy: float = 0.5
    avg_daily_events: float = 25.0
    typical_max_sensitivity: int = 2
    peer_group_id: str = "general"
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class ContextRecord(BaseModel):
    id: str
    user_id: str
    context_type: str  # PROJECT_TRANSFER, ON_CALL_ROTATION, APPROVED_CHANGE_TICKET, TRAVEL_EXEMPTION, MAINTENANCE_WINDOW
    description: str
    ticket_reference: Optional[str] = None
    valid_from: datetime
    valid_until: datetime
    damping_factor: float = 0.35  # Multiplier applied to raw risk score (e.g., 0.35 reduces score by 65%)
    approved_by: str
    target_resources: List[str] = []
    active: bool = True


class ThreatAlert(BaseModel):
    id: str
    user_id: str
    username: str
    department: str
    role: str
    timestamp: datetime
    title: str
    risk_score: float  # 0 to 100
    raw_risk_score: float
    context_damped: bool = False
    damping_reason: Optional[str] = None
    transition_state: TransitionState
    dominant_vectors: List[str] = []
    status: str = "OPEN"  # OPEN, INVESTIGATING, DAMPED_BENIGN, RESOLVED_INCIDENT
    explanation_summary: str
    mitre_tactics: List[str] = []
    assigned_to: Optional[str] = None
    triage_notes: List[str] = []


class UserSummary(BaseModel):
    user_id: str
    username: str
    department: str
    role: str
    current_risk_score: float
    transition_state: TransitionState
    dominant_vector: str
    event_count_30d: int
    has_active_context: bool
    context_description: Optional[str] = None
    alert_count: int


class ExplainabilityPayload(BaseModel):
    user_id: str
    username: str
    department: str
    role: str
    composite_risk_score: float
    raw_risk_score: float
    is_context_damped: bool
    damping_reason: Optional[str]
    transition_state: TransitionState
    vector_scores: Dict[str, float]  # temporal, entropy, privilege, peer_divergence, velocity
    baseline_vs_actual: Dict[str, Any]
    natural_language_brief: str
    mitre_mapping: List[Dict[str, str]]
    contributing_events: List[Dict[str, Any]]
    contextual_factors: List[ContextRecord]
    playbook_recommendations: List[str]
    peer_comparison: Dict[str, Any]


class TriageActionRequest(BaseModel):
    action: str  # STEP_UP_MFA, QUARANTINE_SESSION, DAMP_WITH_CONTEXT, RE_BASELINE, ESCALATE_TICKET
    notes: Optional[str] = None
    ticket_id: Optional[str] = None


class CustomEventRequest(BaseModel):
    user_id: str
    event_type: EventType
    resource: str
    sensitivity_level: int = 3
    action: str
    is_off_hours: bool = False
    context_tags: List[str] = []

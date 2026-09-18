/** Types mirroring the Aegis Drift REST API. */

export type TransitionState = 'STABLE' | 'EARLY_DRIFT' | 'ESCALATING' | 'CRITICAL_TRANSITION'
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type AlertStatus =
  | 'OPEN'
  | 'TRIAGED'
  | 'INVESTIGATING'
  | 'SUPPRESSED'
  | 'FALSE_POSITIVE'
  | 'CONFIRMED_INCIDENT'
  | 'CLOSED'
export type CaseStatus =
  | 'NEW'
  | 'IN_PROGRESS'
  | 'PENDING_INPUT'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
export type CasePriority = 'P1' | 'P2' | 'P3' | 'P4'
export type Role = 'viewer' | 'analyst' | 'responder' | 'admin'

export type RiskVector =
  | 'temporal'
  | 'resource'
  | 'privilege'
  | 'peer_divergence'
  | 'geovelocity'
  | 'volume'
  | 'device'
  | 'intel'

export interface PageMeta {
  page: number
  page_size: number
  total: number
  total_pages: number
  has_next: boolean
  has_previous: boolean
}

export interface Page<T> {
  items: T[]
  meta: PageMeta
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export interface User {
  id: string
  email: string
  full_name: string
  role: Role
  is_active: boolean
  last_login_at: string | null
  preferences: Record<string, unknown>
  created_at: string
}

export interface Identity {
  id: string
  username: string
  display_name: string
  email: string
  department: string
  role_title: string
  manager: string | null
  location: string
  employment_type: string
  peer_group_id: string
  is_privileged: boolean
  is_service_account: boolean
  is_active: boolean
  is_quarantined: boolean
  on_watchlist: boolean
  risk_score: number
  raw_risk_score: number
  transition_state: TransitionState
  drift_velocity: number
  dominant_vector: string
  vector_scores: Partial<Record<RiskVector, number>>
  event_count: number
  last_event_at: string | null
  last_scored_at: string | null
}

export interface Alert {
  id: string
  identity_id: string
  case_id: string | null
  title: string
  summary: string
  severity: Severity
  status: AlertStatus
  confidence: number
  risk_score: number
  raw_risk_score: number
  transition_state: TransitionState
  drift_velocity: number
  context_damped: boolean
  damping_reason: string | null
  anti_tamper_override: boolean
  dominant_vectors: string[]
  vector_scores: Record<string, number>
  mitre_techniques: string[]
  matched_rule_ids: string[]
  assigned_to_id: string | null
  acknowledged_at: string | null
  resolved_at: string | null
  resolution_note: string | null
  first_seen_at: string
  last_seen_at: string
  occurrence_count: number
  created_at: string
  username?: string | null
  department?: string | null
  role_title?: string | null
}

export interface TimelinePoint {
  event_id: string
  timestamp: string
  resource: string
  action: string
  event_type: string
  sensitivity: number
  event_score: number
  raw_event_score: number
  cumulative_risk: number
  raw_cumulative_risk: number
  is_damped: boolean
  damping_reason: string | null
  anti_tamper: boolean
  matched_rules: string[]
  state: string
  vectors: Record<string, number>
}

export interface AttributionRow {
  vector: string
  label: string
  score: number
  share: number
  explanation: string
}

export interface KeyFinding {
  severity: string
  title: string
  detail: string
  evidence_count: number
}

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  description: string
  detection_hint: string
  confidence: number
  evidence: string[]
}

export interface RecommendedAction {
  action: string
  label: string
  rationale: string
  urgency: string
}

export interface ContributingEvent {
  event_id: string
  timestamp: string
  resource: string
  action: string
  event_type: string
  sensitivity: number
  sensitivity_label: string
  raw_score: number
  damped_score: number
  is_damped: boolean
  anti_tamper: boolean
  matched_rules: string[]
  ip_address: string
  country: string
  bytes: number
  records: number
  top_vectors: string[]
}

export interface PeerComparison {
  cohort: string
  available: boolean
  note?: string
  member_count?: number
  cohort_mean_risk?: number
  cohort_stddev?: number
  identity_risk?: number
  z_score?: number
  percentile?: number
  cohort_mean_daily_events?: number
  cohort_mean_max_sensitivity?: number
  interpretation?: string
}

export interface BaselineComparison {
  circadian_profile: string
  off_hours: { baseline: number; observed: number; unit: string }
  max_sensitivity: {
    baseline: number
    observed: number
    baseline_label: string
    observed_label: string
  }
  daily_events: { baseline: number; observed: number; stddev: number }
  resource_entropy: { baseline: number; observed: number }
  known_resources: string[]
  novel_resources: string[]
  baseline_maturity: number
  baseline_sample_size: number
}

export interface Explanation {
  identity_id: string
  username: string
  headline: string
  narrative: string
  verdict: string
  confidence: number
  attribution: AttributionRow[]
  baseline_comparison: BaselineComparison
  peer_comparison: PeerComparison
  key_findings: KeyFinding[]
  contributing_events: ContributingEvent[]
  mitre_techniques: MitreTechnique[]
  recommended_actions: RecommendedAction[]
  context_factors: Record<string, unknown>[]
  counter_evidence: string[]
}

export interface BlastGraphNode {
  id: string
  label: string
  type: 'identity' | 'category' | 'asset' | 'crown_jewel'
  sublabel: string
  sensitivity: number
  size: number
  records?: number
}

export interface BlastGraphEdge {
  source: string
  target: string
  weight: number
  kind: string
  actions?: string[]
  bytes?: number
}

export interface BlastRadius {
  identity_id: string
  username: string
  blast_radius_score: number
  impact_level: string
  assets_touched: number
  crown_jewels_touched: number
  crown_jewel_names: string[]
  pii_exposed: boolean
  cardholder_data_exposed: boolean
  phi_exposed: boolean
  records_at_risk: number
  estimated_exposure_usd: number
  estimated_exposure_display: string
  lateral_reach: {
    credential_assets_reached: number
    environments: string[]
    downstream_teams: string[]
    estimated_additional_systems: number
    can_escalate_to_admin: boolean
  }
  compliance_impacts: {
    framework: string
    triggered_by: string
    obligation: string
    severity: string
    in_scope_assets: string[]
  }[]
  graph: { nodes: BlastGraphNode[]; edges: BlastGraphEdge[] }
  asset_breakdown: {
    key: string
    name: string
    category: string
    sensitivity: number
    environment: string
    owner_team: string
    crown_jewel: boolean
    pii: boolean
    cardholder: boolean
    records: number
  }[]
}

export interface ContextRecord {
  id: string
  identity_id: string
  context_type: string
  title: string
  description: string
  ticket_reference: string | null
  source_system: string
  valid_from: string
  valid_until: string
  damping_factor: number
  target_resources: string[]
  allowed_actions: string[]
  approved_by: string
  is_active: boolean
  applied_count: number
  created_at: string
  currently_covering?: boolean
}

export interface Investigation {
  identity: Identity & { last_event_at: string | null }
  risk_score: number
  raw_risk_score: number
  transition_state: TransitionState
  drift_velocity: number
  peak_risk: number
  vector_scores: Record<string, number>
  dominant_vectors: string[]
  explanation: Explanation
  blast_radius: BlastRadius
  timeline: TimelinePoint[]
  baseline: Record<string, unknown> | null
  contexts: ContextRecord[]
  alerts: {
    id: string
    title: string
    severity: string
    status: string
    risk_score: number
    created_at: string
    occurrence_count: number
    case_id: string | null
  }[]
  actions: {
    id: string
    action: string
    outcome: string
    performed_by: string
    is_automated: boolean
    notes: string | null
    created_at: string
  }[]
  matched_rules: {
    id: string
    slug: string
    name: string
    severity: string
    risk_boost: number
    mitre_techniques: string[]
  }[]
  event_count: number
  generated_at: string
}

export interface Overview {
  kpis: {
    monitored_identities: number
    active_threat_transitions: number
    critical_identities: number
    open_alerts: number
    open_cases: number
    suppressed_false_positives: number
    fleet_health_score: number
    mean_risk_score: number
    events_last_24h: number
    anti_tamper_events: number
  }
  transition_distribution: { key: string; label: string; count: number; percentage: number }[]
  severity_distribution: { key: string; label: string; count: number; percentage: number }[]
  department_risk: {
    department: string
    identity_count: number
    mean_risk: number
    max_risk: number
    at_risk_count: number
    privileged_count: number
  }[]
  vector_heatmap: Record<string, number>
  risk_trend: { timestamp: string; value: number; label: string | null }[]
  event_volume_trend: { timestamp: string; value: number; label: string | null }[]
  top_alerts: Alert[]
  top_risky_identities: Identity[]
  recent_actions: {
    id: string
    action: string
    identity_id: string
    username: string
    outcome: string
    performed_by: string
    is_automated: boolean
    created_at: string
  }[]
  peer_outliers: {
    identity_id: string
    username: string
    cohort: string
    risk_score: number
    cohort_mean: number
    z_score: number
  }[]
  generated_at: string
}

export interface Case {
  id: string
  reference: string
  title: string
  description: string
  status: CaseStatus
  priority: CasePriority
  severity: Severity
  primary_identity_id: string | null
  assignee_id: string | null
  tags: string[]
  mitre_techniques: string[]
  peak_risk_score: number
  blast_radius_score: number
  estimated_records_at_risk: number
  sla_due_at: string | null
  acknowledged_at: string | null
  contained_at: string | null
  closed_at: string | null
  closure_reason: string | null
  created_at: string
  updated_at: string
  entries?: CaseEntry[]
  alerts?: Alert[]
}

export interface CaseEntry {
  id: string
  case_id: string
  entry_type: string
  author_id: string | null
  author_label: string
  body: string
  entry_metadata: Record<string, unknown>
  created_at: string
}

export interface DetectionRule {
  id: string
  slug: string
  name: string
  description: string
  category: string
  severity: Severity
  enabled: boolean
  is_builtin: boolean
  conditions: Record<string, unknown>
  risk_boost: number
  mitre_techniques: string[]
  recommended_actions: string[]
  suppress_when_context: boolean
  match_count: number
  true_positive_count: number
  false_positive_count: number
  last_matched_at: string | null
}

export interface Scenario {
  id: string
  title: string
  subtitle: string
  narrative: string
  target_username: string
  expected_outcome: string
  expected_state: TransitionState
  expect_exact: boolean
  teaches: string
  event_count: number
  duration_days: number
}

export interface ScenarioResult {
  scenario: Scenario
  identity_id: string
  events_injected: number
  risk_before: number
  risk_after: number
  state_before: TransitionState
  state_after: TransitionState
  alert_id: string | null
  damping_applied: boolean
  anti_tamper_triggered: boolean
  matched_rules: string[]
  outcome_matches_expectation: boolean
}

export interface Asset {
  id: string
  key: string
  display_name: string
  category: string
  owner_team: string
  sensitivity_level: number
  environment: string
  contains_pii: boolean
  contains_phi: boolean
  contains_cardholder_data: boolean
  is_crown_jewel: boolean
  record_estimate: number
  compliance_scopes: string[]
  tags: string[]
}

export interface Indicator {
  id: string
  indicator_type: string
  value: string
  confidence: number
  severity: string
  source_feed: string
  description: string | null
  first_seen: string | null
  last_seen: string | null
  expires_at: string | null
  hit_count: number
  is_active: boolean
}

export interface Integration {
  id: string
  name: string
  kind: string
  vendor: string
  status: string
  protocol: string
  sync_interval: string
  last_heartbeat_at: string | null
  entities_synced: number
  events_ingested_24h: number
  error_message: string | null
}

export interface Playbook {
  id: string
  slug: string
  name: string
  description: string
  category: string
  steps: { action: string; label: string; description: string }[]
  trigger_conditions: Record<string, unknown>
  auto_execute: boolean
  requires_approval: boolean
  enabled: boolean
  estimated_minutes: number
  run_count: number
  last_run_at: string | null
}

export interface EnterpriseMetrics {
  mttd_hours: number
  mttd_industry_baseline_hours: number
  mttd_reduction_percentage: number
  mttr_hours: number
  alerts_per_analyst_day: number
  false_positive_rate: number
  noise_suppression_percentage: number
  analyst_hours_saved_monthly: number
  detection_coverage_percentage: number
  records_protected: number
  exposure_under_management_usd: number
  exposure_under_management_display: string
  compliance: {
    framework: string
    control_reference: string
    status: string
    coverage_percentage: number
    evidence: string[]
    gaps: string[]
    last_assessed: string
  }[]
  methodology_note: string
}

export interface MitreCoverage {
  matrix: {
    tactic: string
    total: number
    observed: number
    techniques: { id: string; name: string; observed: boolean; description: string }[]
  }[]
  observed_count: number
  catalog_size: number
  coverage_percentage: number
  observed_techniques: string[]
}

export interface CopilotAnswer {
  intent: string
  answer: string
  confidence: number
  citations: { type: string; label: string; ref: string; timestamp?: string; score?: number }[]
  follow_ups: string[]
  data: Record<string, unknown>
  identity_id: string
  conversation_id: string | null
  answered_at: string
}

export interface Hyperparameters {
  decay_halflife_hours: number
  normal_threshold: number
  threshold_early_drift: number
  threshold_escalating: number
  threshold_critical: number
  vector_weights: Record<string, number>
  synergy_elevated_at: number
}

export interface LiveEvent {
  type: string
  payload: Record<string, unknown>
  at?: string
}

export interface AuditEntry {
  id: string
  created_at: string
  actor_email: string
  action: string
  target_type: string
  target_id: string | null
  outcome: string
  ip_address: string | null
  request_id: string | null
  payload: Record<string, unknown>
}

export interface RecentEvent {
  id: string
  identity_id: string
  username: string
  department: string
  occurred_at: string
  event_type: string
  resource: string
  action: string
  sensitivity_level: number
  anomaly_score: number
  is_damped: boolean
  is_off_hours: boolean
  country: string
  matched_rules: string[]
}

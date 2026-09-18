/** TanStack Query hooks — one place that knows every endpoint and its cache policy. */

import { useMutation, useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type {
  Alert,
  Asset,
  AuditEntry,
  Case,
  CaseEntry,
  CopilotAnswer,
  DetectionRule,
  EnterpriseMetrics,
  Hyperparameters,
  Identity,
  Indicator,
  Integration,
  Investigation,
  MitreCoverage,
  Overview,
  Page,
  Playbook,
  RecentEvent,
  Scenario,
  ScenarioResult,
  User,
} from '@/types/api'

export const keys = {
  overview: ['overview'] as const,
  identities: (params: unknown) => ['identities', params] as const,
  identity: (id: string) => ['identity', id] as const,
  investigation: (id: string) => ['investigation', id] as const,
  alerts: (params: unknown) => ['alerts', params] as const,
  alertStats: ['alerts', 'stats'] as const,
  cases: (params: unknown) => ['cases', params] as const,
  caseDetail: (id: string) => ['case', id] as const,
  caseStats: ['cases', 'stats'] as const,
  rules: (params: unknown) => ['rules', params] as const,
  ruleStats: ['rules', 'stats'] as const,
  contexts: (params: unknown) => ['contexts', params] as const,
  assets: (params: unknown) => ['assets', params] as const,
  assetSummary: ['assets', 'summary'] as const,
  indicators: (params: unknown) => ['indicators', params] as const,
  integrations: ['integrations'] as const,
  playbooks: ['playbooks'] as const,
  scenarios: ['scenarios'] as const,
  metrics: ['metrics'] as const,
  mitre: ['mitre'] as const,
  audit: (params: unknown) => ['audit', params] as const,
  hyperparameters: ['hyperparameters'] as const,
  recentEvents: ['events', 'recent'] as const,
  eventStats: ['events', 'stats'] as const,
  departments: ['departments'] as const,
  users: ['users'] as const,
  estate: ['estate'] as const,
}

/** The dashboard is the one view where staleness is most visible. */
const LIVE = { staleTime: 10_000, refetchInterval: 30_000 }
const STATIC = { staleTime: 5 * 60_000 }

export function useOverview() {
  return useQuery({ queryKey: keys.overview, queryFn: () => api.get<Overview>('/analytics/overview'), ...LIVE })
}

export function useIdentities(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.identities(params),
    queryFn: () => api.get<Page<Identity>>('/identities', params as never),
    placeholderData: keepPreviousData,
    staleTime: 15_000,
  })
}

export function useDepartments() {
  return useQuery({
    queryKey: keys.departments,
    queryFn: () => api.get<string[]>('/identities/departments'),
    ...STATIC,
  })
}

export function useInvestigation(identityId: string | undefined) {
  return useQuery({
    queryKey: keys.investigation(identityId ?? ''),
    queryFn: () => api.get<Investigation>(`/identities/${identityId}/investigation`),
    enabled: Boolean(identityId),
    staleTime: 20_000,
  })
}

export function useAlerts(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.alerts(params),
    queryFn: () => api.get<Page<Alert>>('/alerts', params as never),
    placeholderData: keepPreviousData,
    ...LIVE,
  })
}

export function useAlertStats() {
  return useQuery({ queryKey: keys.alertStats, queryFn: () => api.get<Record<string, never>>('/alerts/stats'), ...LIVE })
}

export function useCases(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.cases(params),
    queryFn: () => api.get<Page<Case>>('/cases', params as never),
    placeholderData: keepPreviousData,
    staleTime: 15_000,
  })
}

export function useCase(caseId: string | undefined) {
  return useQuery({
    queryKey: keys.caseDetail(caseId ?? ''),
    queryFn: () => api.get<Case>(`/cases/${caseId}`),
    enabled: Boolean(caseId),
  })
}

export function useCaseStats() {
  return useQuery({ queryKey: keys.caseStats, queryFn: () => api.get<Record<string, never>>('/cases/stats'), ...LIVE })
}

export function useRules(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.rules(params),
    queryFn: () => api.get<Page<DetectionRule>>('/detections', params as never),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  })
}

export function useRuleStats() {
  return useQuery({
    queryKey: keys.ruleStats,
    queryFn: () => api.get<Record<string, never>>('/detections/stats'),
    staleTime: 30_000,
  })
}

export function useContexts(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.contexts(params),
    queryFn: () => api.get<Page<never>>('/contexts', params as never),
    placeholderData: keepPreviousData,
    staleTime: 20_000,
  })
}

export function useAssets(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.assets(params),
    queryFn: () => api.get<Page<Asset>>('/catalog/assets', params as never),
    placeholderData: keepPreviousData,
    ...STATIC,
  })
}

export function useAssetSummary() {
  return useQuery({
    queryKey: keys.assetSummary,
    queryFn: () => api.get<Record<string, never>>('/catalog/assets/summary'),
    ...STATIC,
  })
}

export function useIndicators(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.indicators(params),
    queryFn: () => api.get<Page<Indicator>>('/catalog/indicators', params as never),
    ...STATIC,
  })
}

export function useIntegrations() {
  return useQuery({
    queryKey: keys.integrations,
    queryFn: () => api.get<Integration[]>('/analytics/integrations'),
    staleTime: 60_000,
  })
}

export function usePlaybooks() {
  return useQuery({ queryKey: keys.playbooks, queryFn: () => api.get<Playbook[]>('/response/playbooks'), ...STATIC })
}

export function useScenarios() {
  return useQuery({
    queryKey: keys.scenarios,
    queryFn: () => api.get<Scenario[]>('/simulator/scenarios'),
    ...STATIC,
  })
}

export function useEstate() {
  return useQuery({
    queryKey: keys.estate,
    queryFn: () => api.get<Record<string, number>>('/simulator/estate'),
    staleTime: 20_000,
  })
}

export function useEnterpriseMetrics() {
  return useQuery({
    queryKey: keys.metrics,
    queryFn: () => api.get<EnterpriseMetrics>('/analytics/metrics'),
    staleTime: 60_000,
  })
}

export function useMitreCoverage() {
  return useQuery({
    queryKey: keys.mitre,
    queryFn: () => api.get<MitreCoverage>('/analytics/mitre/coverage'),
    staleTime: 60_000,
  })
}

export function useAuditTrail(params: Record<string, unknown>) {
  return useQuery({
    queryKey: keys.audit(params),
    queryFn: () => api.get<Page<AuditEntry>>('/analytics/audit', params as never),
    placeholderData: keepPreviousData,
    staleTime: 15_000,
  })
}

export function useHyperparameters() {
  return useQuery({
    queryKey: keys.hyperparameters,
    queryFn: () => api.get<Hyperparameters>('/analytics/hyperparameters'),
    staleTime: 60_000,
  })
}

export function useRecentEvents(limit = 60) {
  return useQuery({
    queryKey: [...keys.recentEvents, limit],
    queryFn: () => api.get<RecentEvent[]>('/events/recent', { limit }),
    staleTime: 5_000,
  })
}

export function useEventStats() {
  return useQuery({
    queryKey: keys.eventStats,
    queryFn: () => api.get<Record<string, never>>('/events/stats'),
    staleTime: 20_000,
  })
}

export function useOperators() {
  return useQuery({ queryKey: keys.users, queryFn: () => api.get<User[]>('/auth/users'), ...STATIC })
}

/* ------------------------------------------------------------------ mutations */

/** Anything that changes risk invalidates broadly — correctness over precision. */
function invalidateRiskSurfaces(qc: ReturnType<typeof useQueryClient>) {
  for (const key of ['overview', 'identities', 'identity', 'investigation', 'alerts', 'estate', 'metrics']) {
    void qc.invalidateQueries({ queryKey: [key] })
  }
}

export function useRunScenario() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (scenarioId: string) =>
      api.post<ScenarioResult>(`/simulator/scenarios/${scenarioId}/run`, {}),
    onSuccess: () => invalidateRiskSurfaces(qc),
  })
}

export function useResetEstate() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post<{ message: string }>('/simulator/reset'),
    onSuccess: () => qc.invalidateQueries(),
  })
}

export function useExecuteAction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (vars: { identityId: string; action: string; notes?: string; caseId?: string }) =>
      api.post(`/response/identities/${vars.identityId}/actions`, {
        action: vars.action,
        notes: vars.notes,
        case_id: vars.caseId,
      }),
    onSuccess: () => invalidateRiskSurfaces(qc),
  })
}

export function useRunPlaybook() {
  return useMutation({
    mutationFn: (vars: { slug: string; identityId: string; dryRun: boolean; caseId?: string }) =>
      api.post<{ steps: { step: number; action: string; label: string; outcome: string }[] }>(
        `/response/playbooks/${vars.slug}/run`,
        { identity_id: vars.identityId, dry_run: vars.dryRun, case_id: vars.caseId },
      ),
  })
}

export function useAskCopilot() {
  return useMutation({
    mutationFn: (vars: { identityId: string; question: string }) =>
      api.post<CopilotAnswer>(`/identities/${vars.identityId}/copilot`, {
        identity_id: vars.identityId,
        question: vars.question,
      }),
  })
}

export function useUpdateAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (vars: { id: string; body: Record<string, unknown> }) =>
      api.patch<Alert>(`/alerts/${vars.id}`, vars.body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['alerts'] })
      void qc.invalidateQueries({ queryKey: ['overview'] })
    },
  })
}

export function useAssignAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post<Alert>(`/alerts/${id}/assign`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

export function useCreateCase() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Case>('/cases', body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['cases'] })
      void qc.invalidateQueries({ queryKey: ['alerts'] })
    },
  })
}

export function useUpdateCase() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (vars: { id: string; body: Record<string, unknown> }) =>
      api.patch<Case>(`/cases/${vars.id}`, vars.body),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: keys.caseDetail(vars.id) })
      void qc.invalidateQueries({ queryKey: ['cases'] })
    },
  })
}

export function useAddCaseEntry() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (vars: { caseId: string; body: string }) =>
      api.post<CaseEntry>(`/cases/${vars.caseId}/entries`, { body: vars.body }),
    onSuccess: (_data, vars) => void qc.invalidateQueries({ queryKey: keys.caseDetail(vars.caseId) }),
  })
}

export function useToggleRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (vars: { id: string; enabled: boolean }) =>
      api.patch<DetectionRule>(`/detections/${vars.id}`, { enabled: vars.enabled }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['rules'] })
    },
  })
}

export function useTestRule() {
  return useMutation({
    mutationFn: (conditions: Record<string, unknown>) =>
      api.post<{ valid: boolean; matched: boolean; error: string | null; facts: Record<string, unknown> }>(
        '/detections/test',
        { conditions },
      ),
  })
}

export function useCreateContext() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/contexts', body),
    onSuccess: (_d, _v) => {
      void qc.invalidateQueries({ queryKey: ['contexts'] })
      invalidateRiskSurfaces(qc)
    },
  })
}

export function useRevokeContext() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/contexts/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['contexts'] })
      invalidateRiskSurfaces(qc)
    },
  })
}

export function useRebuildBaseline() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (identityId: string) => api.post(`/identities/${identityId}/baseline/rebuild`),
    onSuccess: () => invalidateRiskSurfaces(qc),
  })
}

export function useUpdateHyperparameters() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.put<Hyperparameters>('/analytics/hyperparameters', body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.hyperparameters })
      invalidateRiskSurfaces(qc)
    },
  })
}

export function useInjectEvent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/events/ingest/single', body),
    onSuccess: () => {
      invalidateRiskSurfaces(qc)
      void qc.invalidateQueries({ queryKey: ['events'] })
    },
  })
}

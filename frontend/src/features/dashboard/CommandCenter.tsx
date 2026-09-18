import { Link } from 'react-router-dom'
import { useOverview } from '@/lib/queries'
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Panel,
  PanelHeader,
  Skeleton,
  Stat,
} from '@/components/ui'
import {
  DepartmentRisk,
  StateDistribution,
  VectorHeatmap,
  VolumeTrend,
} from '@/components/charts'
import {
  compactNumber,
  percent,
  relativeTime,
  riskTextClass,
  STATE_META,
  SEVERITY_META,
  titleise,
} from '@/lib/format'
import { cn } from '@/lib/utils'
import { IconAlert, IconArrowDown, IconArrowUp, IconBolt, IconShield } from '@/components/ui/icons'
import type { Severity, TransitionState } from '@/types/api'

export function CommandCenter() {
  const { data, isLoading, error, refetch } = useOverview()

  if (isLoading) return <DashboardSkeleton />
  if (error) return <ErrorState error={error} retry={() => void refetch()} />
  if (!data) return null

  const { kpis } = data

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Command Center</h1>
          <p className="mt-0.5 text-xs text-[--color-ink-muted]">
            Fleet posture across {kpis.monitored_identities} monitored identities · refreshed{' '}
            {relativeTime(data.generated_at)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge dot={kpis.anti_tamper_events > 0 ? 'bg-rose-400 animate-pulse-ring' : 'bg-emerald-400'}>
            {kpis.anti_tamper_events > 0
              ? `${kpis.anti_tamper_events} anti-tamper event${kpis.anti_tamper_events === 1 ? '' : 's'}`
              : 'No tampering detected'}
          </Badge>
          <Button size="sm" onClick={() => void refetch()}>
            Refresh
          </Button>
        </div>
      </header>

      {/* ------------------------------------------------------------- KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        <KpiCard
          label="Fleet health"
          value={kpis.fleet_health_score.toFixed(0)}
          suffix="/100"
          accent={kpis.fleet_health_score >= 80 ? 'var(--color-stable)' : kpis.fleet_health_score >= 55 ? 'var(--color-drift)' : 'var(--color-critical)'}
          sublabel={`Mean risk ${kpis.mean_risk_score.toFixed(1)}`}
        />
        <KpiCard
          label="Active transitions"
          value={String(kpis.active_threat_transitions)}
          accent={kpis.active_threat_transitions > 0 ? 'var(--color-escalating)' : 'var(--color-stable)'}
          sublabel="Escalating or critical"
        />
        <KpiCard
          label="Critical identities"
          value={String(kpis.critical_identities)}
          accent={kpis.critical_identities > 0 ? 'var(--color-critical)' : 'var(--color-stable)'}
          sublabel="Containment recommended"
        />
        <KpiCard
          label="Open alerts"
          value={String(kpis.open_alerts)}
          sublabel={`${kpis.open_cases} case${kpis.open_cases === 1 ? '' : 's'} in flight`}
        />
        <KpiCard
          label="Suppressed"
          value={String(kpis.suppressed_false_positives)}
          accent="var(--color-suppressed)"
          sublabel="Explained by approved context"
        />
        <KpiCard
          label="Events / 24h"
          value={compactNumber(kpis.events_last_24h)}
          sublabel="Telemetry ingested"
        />
      </div>

      {/* ----------------------------------------------------- charts row 1 */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel lit className="xl:col-span-2">
          <PanelHeader
            title="Prioritised triage feed"
            subtitle="Highest-risk open alerts, ordered by composite score"
            action={
              <Link to="/alerts">
                <Button size="sm" variant="ghost">
                  View queue →
                </Button>
              </Link>
            }
          />
          {data.top_alerts.length === 0 ? (
            <EmptyState
              icon={<IconShield className="size-8" />}
              title="No open alerts"
              description="Every monitored identity is inside its behavioural envelope. Run a scenario from the Threat Simulator to exercise the detection pipeline."
              action={
                <Link to="/simulator">
                  <Button size="sm" variant="primary">
                    Open the simulator
                  </Button>
                </Link>
              }
            />
          ) : (
            <ul className="divide-y divide-[--color-border-subtle]">
              {data.top_alerts.map((alert) => (
                <li key={alert.id}>
                  <Link
                    to={`/investigate/${alert.identity_id}`}
                    className="flex items-start gap-3 px-5 py-3 transition-colors hover:bg-white/[0.025]"
                  >
                    <RiskDial score={alert.risk_score} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate text-sm font-medium">{alert.username ?? alert.identity_id}</span>
                        <StateBadge state={alert.transition_state} />
                        {alert.anti_tamper_override && (
                          <Badge className="border-rose-500/40 bg-rose-500/10 text-rose-300">Anti-tamper</Badge>
                        )}
                        {alert.context_damped && (
                          <Badge className="border-indigo-500/30 bg-indigo-500/10 text-indigo-300">Damped</Badge>
                        )}
                      </div>
                      <p className="mt-0.5 truncate text-xs text-[--color-ink-muted]">{alert.title}</p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[--color-ink-faint]">
                        <span>{alert.department}</span>
                        <span>·</span>
                        <span>{alert.dominant_vectors.map((v) => titleise(v)).join(', ')}</span>
                        {alert.mitre_techniques.length > 0 && (
                          <>
                            <span>·</span>
                            <span className="font-mono">{alert.mitre_techniques.slice(0, 3).join(' ')}</span>
                          </>
                        )}
                        <span>·</span>
                        <span>{relativeTime(alert.created_at)}</span>
                      </div>
                    </div>
                    <div className="shrink-0 text-right">
                      <SeverityBadge severity={alert.severity} />
                      <p className="mt-1.5 text-[10px] text-[--color-ink-faint]">
                        {alert.confidence.toFixed(0)}% confidence
                      </p>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <div className="space-y-4">
          <Panel>
            <PanelHeader title="Transition spectrum" subtitle="Where the fleet sits right now" />
            <div className="px-5 pt-2">
              <StateDistribution distribution={data.transition_distribution} />
            </div>
            <ul className="space-y-1.5 px-5 pb-4">
              {data.transition_distribution.map((slice) => {
                const meta = STATE_META[slice.key as TransitionState]
                return (
                  <li key={slice.key} className="flex items-center gap-2 text-xs">
                    <span className="size-2 rounded-full" style={{ backgroundColor: meta?.color }} />
                    <span className="flex-1 text-[--color-ink-muted]">{meta?.label ?? slice.label}</span>
                    <span className="numeric text-[--color-ink]">{slice.count}</span>
                    <span className="numeric w-10 text-right text-[--color-ink-faint]">
                      {percent(slice.percentage)}
                    </span>
                  </li>
                )
              })}
            </ul>
          </Panel>

          <Panel>
            <PanelHeader
              title="Dominant drift vectors"
              subtitle="Mean vector scores across drifting identities only"
            />
            <VectorHeatmap scores={data.vector_heatmap} />
          </Panel>
        </div>
      </div>

      {/* ----------------------------------------------------- charts row 2 */}
      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <Panel>
          <PanelHeader title="Risk by department" subtitle="Mean composite risk per business unit" />
          <div className="px-3 py-3">
            <DepartmentRisk rows={data.department_risk} />
          </div>
        </Panel>

        <Panel>
          <PanelHeader
            title="Telemetry volume"
            subtitle="Daily event count, anomalous share in the tooltip"
          />
          <div className="px-3 py-3">
            <VolumeTrend points={data.event_volume_trend} label="Events" />
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Fleet risk trend" subtitle="Mean risk across periodic snapshots" />
          <div className="px-3 py-3">
            <VolumeTrend points={data.risk_trend} color="#fb923c" label="Mean risk" />
          </div>
        </Panel>
      </div>

      {/* ----------------------------------------------------- charts row 3 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel>
          <PanelHeader
            title="Cohort outliers"
            subtitle="Identities furthest from their own peer group"
            icon={<IconBolt className="size-4" />}
          />
          {data.peer_outliers.length === 0 ? (
            <EmptyState title="No cohort outliers" description="Every identity sits within its peer group's normal range." />
          ) : (
            <ul className="divide-y divide-[--color-border-subtle]">
              {data.peer_outliers.slice(0, 6).map((outlier) => (
                <li key={outlier.identity_id}>
                  <Link
                    to={`/investigate/${outlier.identity_id}`}
                    className="flex items-center gap-3 px-5 py-2.5 transition-colors hover:bg-white/[0.025]"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-medium">{outlier.username}</p>
                      <p className="truncate text-[11px] text-[--color-ink-faint]">{outlier.cohort}</p>
                    </div>
                    <div className="text-right">
                      <p className={cn('numeric text-xs font-semibold', riskTextClass(outlier.risk_score))}>
                        {outlier.risk_score.toFixed(0)}
                      </p>
                      <p className="numeric text-[10px] text-[--color-ink-faint]">
                        {outlier.z_score > 0 ? '+' : ''}
                        {outlier.z_score.toFixed(1)}σ
                      </p>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel>
          <PanelHeader title="Highest risk identities" subtitle="Ranked by composite score" />
          <ul className="divide-y divide-[--color-border-subtle]">
            {data.top_risky_identities.slice(0, 6).map((identity) => (
              <li key={identity.id}>
                <Link
                  to={`/investigate/${identity.username}`}
                  className="flex items-center gap-3 px-5 py-2.5 transition-colors hover:bg-white/[0.025]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-xs font-medium">{identity.username}</span>
                      {identity.is_quarantined && (
                        <Badge className="border-rose-500/30 bg-rose-500/10 py-0 text-[9px] text-rose-300">
                          Quarantined
                        </Badge>
                      )}
                      {identity.on_watchlist && (
                        <Badge className="border-amber-500/30 bg-amber-500/10 py-0 text-[9px] text-amber-300">
                          Watchlist
                        </Badge>
                      )}
                    </div>
                    <p className="truncate text-[11px] text-[--color-ink-faint]">
                      {identity.role_title} · {identity.department}
                    </p>
                  </div>
                  <VelocityIndicator velocity={identity.drift_velocity} />
                  <p className={cn('numeric w-8 text-right text-xs font-semibold', riskTextClass(identity.risk_score))}>
                    {identity.risk_score.toFixed(0)}
                  </p>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel>
          <PanelHeader
            title="Recent response actions"
            subtitle="Containment executed across the fleet"
            icon={<IconAlert className="size-4" />}
          />
          {data.recent_actions.length === 0 ? (
            <EmptyState title="No actions taken" description="Containment actions appear here once an analyst or playbook executes one." />
          ) : (
            <ul className="divide-y divide-[--color-border-subtle]">
              {data.recent_actions.slice(0, 6).map((action) => (
                <li key={action.id} className="flex items-center gap-3 px-5 py-2.5">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs font-medium">{titleise(action.action)}</p>
                    <p className="truncate text-[11px] text-[--color-ink-faint]">
                      {action.username} · {action.is_automated ? 'automated' : action.performed_by}
                    </p>
                  </div>
                  <span className="shrink-0 text-[10px] text-[--color-ink-faint]">
                    {relativeTime(action.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ pieces */

function KpiCard({
  label,
  value,
  suffix,
  sublabel,
  accent,
}: {
  label: string
  value: string
  suffix?: string
  sublabel?: string
  accent?: string
}) {
  return (
    <Panel lit className="px-4 py-3.5">
      <Stat
        label={label}
        value={
          <>
            {value}
            {suffix && <span className="text-sm text-[--color-ink-faint]">{suffix}</span>}
          </>
        }
        sublabel={sublabel}
        accent={accent}
      />
    </Panel>
  )
}

export function StateBadge({ state }: { state: TransitionState }) {
  const meta = STATE_META[state]
  return (
    <Badge className={cn(meta.bg, meta.border, meta.text)} dot={meta.dot}>
      {meta.label}
    </Badge>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity]
  return <Badge className={cn(meta.bg, meta.border, meta.text)}>{meta.label}</Badge>
}

export function VelocityIndicator({ velocity }: { velocity: number }) {
  if (Math.abs(velocity) < 0.5) {
    return <span className="w-12 text-right text-[10px] text-[--color-ink-faint]">steady</span>
  }
  const rising = velocity > 0
  return (
    <span
      className={cn(
        'inline-flex w-12 items-center justify-end gap-0.5 text-[10px]',
        rising ? 'text-orange-300' : 'text-emerald-300',
      )}
      title={`${rising ? 'Rising' : 'Decaying'} at ${Math.abs(velocity).toFixed(1)} risk points per day`}
    >
      {rising ? <IconArrowUp className="size-3" /> : <IconArrowDown className="size-3" />}
      <span className="numeric">{Math.abs(velocity).toFixed(0)}</span>
    </span>
  )
}

/** Compact radial risk readout — reads as a gauge at 36px. */
export function RiskDial({ score, size = 36 }: { score: number; size?: number }) {
  const radius = (size - 4) / 2
  const circumference = 2 * Math.PI * radius
  const color =
    score >= 75 ? '#f43f5e' : score >= 50 ? '#fb923c' : score >= 28 ? '#fbbf24' : '#34d399'

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1b2430" strokeWidth="3" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - Math.min(score, 100) / 100)}
          className="transition-all duration-700"
        />
      </svg>
      <span
        className="numeric absolute inset-0 flex items-center justify-center text-[11px] font-semibold"
        style={{ color }}
      >
        {score.toFixed(0)}
      </span>
    </div>
  )
}

function DashboardSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-56" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Skeleton className="h-96 xl:col-span-2" />
        <Skeleton className="h-96" />
      </div>
    </div>
  )
}

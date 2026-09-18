import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useInvestigation, useRebuildBaseline } from '@/lib/queries'
import { useAuth } from '@/lib/auth'
import { downloadText } from '@/lib/api'
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Panel,
  PanelHeader,
  Skeleton,
  Tabs,
} from '@/components/ui'
import { IconDownload, IconRefresh, IconShield } from '@/components/ui/icons'
import { RiskTrajectory, VectorRadar } from '@/components/charts'
import { RiskDial, StateBadge, VelocityIndicator } from '@/features/dashboard/CommandCenter'
import { OverviewTab } from '@/features/investigate/tabs/OverviewTab'
import { TimelineTab } from '@/features/investigate/tabs/TimelineTab'
import { BlastRadiusTab } from '@/features/investigate/tabs/BlastRadiusTab'
import { BaselineTab } from '@/features/investigate/tabs/BaselineTab'
import { MitreTab } from '@/features/investigate/tabs/MitreTab'
import { CopilotTab } from '@/features/investigate/tabs/CopilotTab'
import { ResponseTab } from '@/features/investigate/tabs/ResponseTab'
import { relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'

type TabId = 'overview' | 'timeline' | 'blast' | 'baseline' | 'mitre' | 'copilot' | 'response'

export function InvestigatorWorkbench() {
  const { identityId } = useParams<{ identityId: string }>()
  const { can } = useAuth()
  const { data, isLoading, error, refetch, isFetching } = useInvestigation(identityId)
  const rebuild = useRebuildBaseline()
  const [tab, setTab] = useState<TabId>('overview')
  const [exporting, setExporting] = useState(false)

  if (isLoading) return <WorkbenchSkeleton />
  if (error) return <ErrorState error={error} retry={() => void refetch()} />
  if (!data) return null

  const { identity, explanation, blast_radius: blast } = data

  const exportDossier = async () => {
    setExporting(true)
    try {
      await downloadText(
        `/export/identities/${identity.id}/dossier.md`,
        `aegisdrift-dossier-${identity.username}.md`,
      )
    } finally {
      setExporting(false)
    }
  }

  const tabs: { id: TabId; label: string; count?: number }[] = [
    { id: 'overview', label: 'Assessment' },
    { id: 'timeline', label: 'Timeline', count: data.timeline.length },
    { id: 'blast', label: 'Blast radius', count: blast.assets_touched },
    { id: 'baseline', label: 'Baseline' },
    { id: 'mitre', label: 'ATT&CK', count: explanation.mitre_techniques.length },
    { id: 'copilot', label: 'Copilot' },
    { id: 'response', label: 'Response', count: data.actions.length },
  ]

  return (
    <div className="space-y-4">
      {/* ----------------------------------------------------------- header */}
      <div className="flex flex-wrap items-center gap-2 text-xs text-[--color-ink-faint]">
        <Link to="/identities" className="transition-colors hover:text-[--color-ink]">
          Identities
        </Link>
        <span>/</span>
        <span className="text-[--color-ink]">{identity.username}</span>
      </div>

      <Panel lit>
        <div className="flex flex-wrap items-start gap-5 px-5 py-4">
          <RiskDial score={data.risk_score} size={60} />

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-lg font-semibold tracking-tight">{identity.display_name}</h1>
              <span className="font-mono text-xs text-[--color-ink-faint]">@{identity.username}</span>
              <StateBadge state={data.transition_state} />
              {identity.is_privileged && (
                <Badge className="border-amber-500/30 bg-amber-500/10 text-amber-300">Privileged</Badge>
              )}
              {identity.is_quarantined && (
                <Badge className="border-rose-500/40 bg-rose-500/10 text-rose-300">Quarantined</Badge>
              )}
              {identity.on_watchlist && (
                <Badge className="border-amber-500/30 bg-amber-500/10 text-amber-300">Watchlist</Badge>
              )}
              {identity.is_service_account && <Badge>Service account</Badge>}
            </div>

            <p className="mt-1 text-xs text-[--color-ink-muted]">
              {identity.role_title} · {identity.department} · {identity.location}
              {identity.manager && ` · reports to ${identity.manager}`}
            </p>

            <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
              <MiniStat label="Raw risk" value={data.raw_risk_score.toFixed(1)} hint="Before context damping" />
              <MiniStat label="Peak" value={data.peak_risk.toFixed(1)} hint="Highest point in this window" />
              <MiniStat
                label="Velocity"
                value={<VelocityIndicator velocity={data.drift_velocity} />}
                hint="Risk change per day"
              />
              <MiniStat label="Events" value={String(data.event_count)} hint="Scored in the current window" />
              <MiniStat
                label="Confidence"
                value={`${explanation.confidence.toFixed(0)}%`}
                hint="Engine confidence in this verdict"
              />
              <MiniStat
                label="Last event"
                value={relativeTime(identity.last_event_at)}
                hint="Most recent telemetry"
              />
            </div>
          </div>

          <div className="flex shrink-0 flex-col items-end gap-2">
            <VerdictPill verdict={explanation.verdict} />
            <div className="flex gap-2">
              <Button size="sm" onClick={() => void refetch()} loading={isFetching} icon={<IconRefresh className="size-3.5" />}>
                Rescore
              </Button>
              <Button size="sm" onClick={() => void exportDossier()} loading={exporting} icon={<IconDownload className="size-3.5" />}>
                Dossier
              </Button>
              {can('analyst') && (
                <Button
                  size="sm"
                  variant="ghost"
                  loading={rebuild.isPending}
                  onClick={() => rebuild.mutate(identity.id)}
                  title="Fold current behaviour into the learned norm"
                >
                  Re-baseline
                </Button>
              )}
            </div>
          </div>
        </div>

        {/* Anti-tamper is the one banner that must never be missed. */}
        {explanation.verdict === 'ANTI_TAMPER_OVERRIDE' && (
          <div className="flex items-start gap-3 border-t border-rose-500/25 bg-rose-500/8 px-5 py-3">
            <IconShield className="mt-0.5 size-4 shrink-0 text-rose-400" />
            <div>
              <p className="text-xs font-semibold text-rose-200">Anti-tamper override engaged</p>
              <p className="mt-0.5 text-xs leading-relaxed text-rose-200/70">
                Actions in this window destroy or disable audit evidence. Policy forbids damping these
                under any approval, so the score shown is unmitigated regardless of the context records
                attached to this identity.
              </p>
            </div>
          </div>
        )}
      </Panel>

      {/* ------------------------------------------------- headline charts */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="xl:col-span-2">
          <PanelHeader
            title="Risk trajectory"
            subtitle="Cumulative risk with exponential decay, against the per-event scores that produced it"
            action={
              <div className="flex items-center gap-3 text-[10px] text-[--color-ink-faint]">
                <span className="inline-flex items-center gap-1">
                  <span className="h-0.5 w-3 bg-cyan-400" /> damped
                </span>
                <span className="inline-flex items-center gap-1">
                  <span className="h-0.5 w-3 border-t border-dashed border-slate-400" /> raw
                </span>
              </div>
            }
          />
          <div className="px-3 py-3">
            {data.timeline.length > 0 ? (
              <RiskTrajectory points={data.timeline} />
            ) : (
              <EmptyState title="No scored events" description="This identity has no telemetry in the correlation window." />
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Vector attribution" subtitle="Which behavioural dimensions drove the verdict" />
          <div className="px-3 py-3">
            <VectorRadar scores={data.vector_scores} />
          </div>
          <ul className="space-y-1 px-5 pb-4">
            {explanation.attribution
              .filter((a) => a.score > 0)
              .slice(0, 4)
              .map((row) => (
                <li key={row.vector} className="flex items-baseline gap-2 text-xs">
                  <span className="flex-1 truncate text-[--color-ink-muted]" title={row.explanation}>
                    {row.label}
                  </span>
                  <span className="numeric text-[--color-ink]">{row.score.toFixed(0)}</span>
                  <span className="numeric w-10 text-right text-[--color-ink-faint]">{row.share.toFixed(0)}%</span>
                </li>
              ))}
          </ul>
        </Panel>
      </div>

      {/* --------------------------------------------------------- tab body */}
      <Panel>
        <Tabs tabs={tabs} active={tab} onChange={setTab} className="px-2" />
        <div className="p-5">
          {tab === 'overview' && <OverviewTab data={data} />}
          {tab === 'timeline' && <TimelineTab data={data} />}
          {tab === 'blast' && <BlastRadiusTab data={data} />}
          {tab === 'baseline' && <BaselineTab data={data} />}
          {tab === 'mitre' && <MitreTab data={data} />}
          {tab === 'copilot' && <CopilotTab data={data} />}
          {tab === 'response' && <ResponseTab data={data} />}
        </div>
      </Panel>
    </div>
  )
}

function MiniStat({ label, value, hint }: { label: string; value: React.ReactNode; hint: string }) {
  return (
    <div title={hint}>
      <p className="text-[10px] tracking-wide text-[--color-ink-faint] uppercase">{label}</p>
      <div className="numeric mt-0.5 text-sm font-medium">{value}</div>
    </div>
  )
}

const VERDICT_STYLE: Record<string, { label: string; className: string }> = {
  ANTI_TAMPER_OVERRIDE: { label: 'Anti-tamper override', className: 'border-rose-500/40 bg-rose-500/15 text-rose-200' },
  CONTAINMENT_RECOMMENDED: { label: 'Containment recommended', className: 'border-rose-500/40 bg-rose-500/15 text-rose-200' },
  INVESTIGATE_NOW: { label: 'Investigate now', className: 'border-orange-500/40 bg-orange-500/15 text-orange-200' },
  MONITOR: { label: 'Monitor', className: 'border-amber-500/30 bg-amber-500/10 text-amber-200' },
  SUPPRESSED_BY_CONTEXT: { label: 'Suppressed by context', className: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-200' },
  NO_ACTION: { label: 'No action required', className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' },
}

export function VerdictPill({ verdict }: { verdict: string }) {
  const style = VERDICT_STYLE[verdict] ?? {
    label: titleise(verdict),
    className: 'border-slate-500/30 bg-slate-500/10 text-slate-200',
  }
  return (
    <span className={cn('rounded-lg border px-2.5 py-1 text-xs font-semibold', style.className)}>
      {style.label}
    </span>
  )
}

function WorkbenchSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-4 w-48" />
      <Skeleton className="h-36" />
      <div className="grid gap-4 xl:grid-cols-3">
        <Skeleton className="h-80 xl:col-span-2" />
        <Skeleton className="h-80" />
      </div>
      <Skeleton className="h-96" />
    </div>
  )
}

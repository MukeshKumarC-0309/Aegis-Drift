import { useEnterpriseMetrics, useIntegrations, useMitreCoverage } from '@/lib/queries'
import { Badge, ErrorState, Panel, PanelHeader, Progress, Skeleton, Stat } from '@/components/ui'
import { compactNumber, percent, relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'

const STATUS_STYLE: Record<string, string> = {
  COMPLIANT: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  PARTIAL: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  GAP: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
}

const INTEGRATION_STATUS: Record<string, string> = {
  CONNECTED: 'bg-emerald-400',
  STREAMING: 'bg-cyan-400',
  DEGRADED: 'bg-amber-400',
  DISCONNECTED: 'bg-slate-500',
}

export function ExecutivePage() {
  const { data, isLoading, error, refetch } = useEnterpriseMetrics()
  const { data: coverage } = useMitreCoverage()
  const { data: integrations } = useIntegrations()

  if (isLoading) return <Skeleton className="h-96" />
  if (error) return <ErrorState error={error} retry={() => void refetch()} />
  if (!data) return null

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Executive view</h1>
        <p className="mt-0.5 text-xs text-[--color-ink-muted]">
          Programme effectiveness measured from this deployment's own data.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        <Panel className="px-4 py-3">
          <Stat
            label="MTTD"
            value={`${data.mttd_hours.toFixed(1)}h`}
            sublabel={`vs ${data.mttd_industry_baseline_hours}h industry`}
            accent="var(--color-stable)"
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="MTTD reduction"
            value={percent(data.mttd_reduction_percentage, 1)}
            sublabel="Against the published baseline"
            accent="var(--color-accent)"
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="MTTR" value={data.mttr_hours ? `${data.mttr_hours.toFixed(1)}h` : '—'} sublabel="Case open to closed" />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Noise suppressed"
            value={percent(data.noise_suppression_percentage, 1)}
            sublabel={`${data.analyst_hours_saved_monthly.toFixed(0)}h saved / month`}
            accent="var(--color-suppressed)"
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="False positive rate"
            value={percent(data.false_positive_rate, 1)}
            sublabel={`${data.alerts_per_analyst_day.toFixed(1)} alerts / analyst / day`}
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Detection coverage"
            value={percent(data.detection_coverage_percentage, 1)}
            sublabel={coverage ? `${coverage.observed_count}/${coverage.catalog_size} ATT&CK techniques` : undefined}
          />
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHeader
            title="Compliance posture"
            subtitle="Control coverage computed from what is actually configured — gaps are stated rather than rounded away."
          />
          <ul className="divide-y divide-[--color-border-subtle]">
            {data.compliance.map((report, i) => (
              <li key={i} className="px-5 py-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{report.framework}</span>
                  <span className="font-mono text-[11px] text-[--color-ink-faint]">
                    {report.control_reference}
                  </span>
                  <Badge className={cn('ml-auto py-0 text-[10px]', STATUS_STYLE[report.status])}>
                    {report.status}
                  </Badge>
                  <span className="numeric w-12 text-right text-xs">
                    {percent(report.coverage_percentage, 1)}
                  </span>
                </div>

                <Progress
                  value={report.coverage_percentage}
                  color={
                    report.coverage_percentage >= 95
                      ? 'var(--color-stable)'
                      : report.coverage_percentage >= 70
                        ? 'var(--color-drift)'
                        : 'var(--color-critical)'
                  }
                  className="mt-2"
                />

                <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
                  <div>
                    <p className="text-[10px] tracking-wider text-[--color-ink-faint] uppercase">Evidence</p>
                    <ul className="mt-0.5 space-y-0.5">
                      {report.evidence.map((item, j) => (
                        <li key={j} className="text-[11px] text-[--color-ink-muted]">
                          · {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                  {report.gaps.length > 0 && (
                    <div>
                      <p className="text-[10px] tracking-wider text-amber-400/70 uppercase">Gaps</p>
                      <ul className="mt-0.5 space-y-0.5">
                        {report.gaps.map((item, j) => (
                          <li key={j} className="text-[11px] text-amber-200/70">
                            · {item}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Panel>

        <div className="space-y-4">
          <Panel>
            <PanelHeader title="Data under protection" />
            <div className="space-y-4 px-5 py-4">
              <Stat
                label="Records monitored"
                value={compactNumber(data.records_protected)}
                sublabel="Across all classified assets"
              />
              <Stat
                label="Exposure under management"
                value={data.exposure_under_management_display}
                sublabel="Modelled cost of an incident on the monitored sensitive assets"
                accent="var(--color-escalating)"
              />
            </div>
          </Panel>

          <Panel>
            <PanelHeader title="Connected systems" subtitle={`${integrations?.length ?? 0} integrations`} />
            <ul className="divide-y divide-[--color-border-subtle]">
              {(integrations ?? []).map((integration) => (
                <li key={integration.id} className="flex items-center gap-2.5 px-5 py-2.5">
                  <span
                    className={cn(
                      'size-1.5 shrink-0 rounded-full',
                      INTEGRATION_STATUS[integration.status] ?? 'bg-slate-500',
                      integration.status === 'STREAMING' && 'animate-pulse-ring',
                    )}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs font-medium">{integration.name}</p>
                    <p className="truncate text-[10px] text-[--color-ink-faint]">
                      {titleise(integration.kind)} · {integration.protocol}
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <p className="text-[10px] text-[--color-ink-muted]">{titleise(integration.status)}</p>
                    <p className="text-[10px] text-[--color-ink-faint]">
                      {relativeTime(integration.last_heartbeat_at)}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>

      <Panel className="border-[--color-border] bg-[--color-surface-raised]">
        <div className="px-5 py-4">
          <p className="text-[10px] font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Methodology
          </p>
          <p className="mt-1.5 text-xs leading-relaxed text-[--color-ink-muted]">
            {data.methodology_note}
          </p>
        </div>
      </Panel>
    </div>
  )
}

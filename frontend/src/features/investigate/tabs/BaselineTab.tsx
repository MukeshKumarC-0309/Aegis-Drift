import type { Investigation } from '@/types/api'
import { Badge, EmptyState, Panel, Progress } from '@/components/ui'
import { CircadianRing } from '@/components/charts'
import { absoluteTime, percent, SENSITIVITY_LABELS } from '@/lib/format'
import { cn } from '@/lib/utils'

export function BaselineTab({ data }: { data: Investigation }) {
  const baseline = data.baseline
  const comparison = data.explanation.baseline_comparison

  if (!baseline) {
    return (
      <EmptyState
        title="No baseline learned yet"
        description="This identity has not accumulated enough history for the engine to model its normal behaviour. Novelty scores will be unreliable until it does."
      />
    )
  }

  const hourly = (baseline.hourly_distribution ?? {}) as Record<string, number>
  const observedHours = [
    ...new Set(
      data.timeline
        .filter((p) => p.raw_event_score >= 45)
        .map((p) => new Date(`${p.timestamp}Z`).getUTCHours()),
    ),
  ]

  const maturity = comparison.baseline_maturity ?? 0

  return (
    <div className="space-y-5">
      {/* Baseline quality gates how much any novelty signal can be trusted. */}
      <div
        className={cn(
          'flex flex-wrap items-center gap-4 rounded-lg border px-4 py-3',
          maturity >= 0.7
            ? 'border-emerald-500/25 bg-emerald-500/5'
            : maturity >= 0.4
              ? 'border-amber-500/25 bg-amber-500/5'
              : 'border-rose-500/25 bg-rose-500/5',
        )}
      >
        <div className="min-w-40 flex-1">
          <div className="flex items-baseline justify-between">
            <p className="text-xs font-medium">Baseline maturity</p>
            <p className="numeric text-xs">{percent(maturity * 100)}</p>
          </div>
          <Progress
            value={maturity * 100}
            color={maturity >= 0.7 ? 'var(--color-stable)' : maturity >= 0.4 ? 'var(--color-drift)' : 'var(--color-critical)'}
            className="mt-1.5"
          />
        </div>
        <p className="flex-[2] text-[11px] leading-relaxed text-[--color-ink-muted]">
          Learned from <span className="numeric">{comparison.baseline_sample_size}</span> events
          {baseline.window_start ? ` between ${absoluteTime(baseline.window_start as string, 'dd MMM')} and ${absoluteTime(baseline.window_end as string, 'dd MMM')}` : ''}
          {' · '}version {String(baseline.version)}.{' '}
          {maturity >= 0.7
            ? 'Mature enough that novelty scores are reliable.'
            : 'Immature — treat novelty scores with caution until more history accumulates.'}
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel>
          <div className="border-b border-[--color-border-subtle] px-5 py-3">
            <h3 className="text-sm font-semibold">Circadian rhythm</h3>
            <p className="mt-0.5 text-xs text-[--color-ink-muted]">{comparison.circadian_profile}</p>
          </div>
          <div className="px-5 py-4">
            <CircadianRing distribution={hourly} observedHours={observedHours} />
            <div className="mt-3 flex items-center justify-center gap-4 text-[10px] text-[--color-ink-faint]">
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-cyan-400" /> learned normal
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-rose-400" /> anomalous activity
              </span>
            </div>
          </div>
        </Panel>

        <Panel className="lg:col-span-2">
          <div className="border-b border-[--color-border-subtle] px-5 py-3">
            <h3 className="text-sm font-semibold">Baseline versus observed</h3>
            <p className="mt-0.5 text-xs text-[--color-ink-muted]">
              What the engine learned as normal, against what it just saw
            </p>
          </div>
          <div className="divide-y divide-[--color-border-subtle]">
            <CompareRow
              label="Off-hours activity"
              baseline={`${comparison.off_hours.baseline}%`}
              observed={`${comparison.off_hours.observed}%`}
              alarming={comparison.off_hours.observed > comparison.off_hours.baseline * 3 + 5}
              note="Share of operations outside working hours"
            />
            <CompareRow
              label="Sensitivity ceiling"
              baseline={`Tier ${comparison.max_sensitivity.baseline} · ${comparison.max_sensitivity.baseline_label}`}
              observed={`Tier ${comparison.max_sensitivity.observed} · ${comparison.max_sensitivity.observed_label}`}
              alarming={comparison.max_sensitivity.observed > comparison.max_sensitivity.baseline}
              note="Highest data classification normally reached"
            />
            <CompareRow
              label="Daily event volume"
              baseline={`${comparison.daily_events.baseline} ± ${comparison.daily_events.stddev}`}
              observed={String(comparison.daily_events.observed)}
              alarming={
                comparison.daily_events.observed >
                comparison.daily_events.baseline + comparison.daily_events.stddev * 2
              }
              note="Events per day, with learned standard deviation"
            />
            <CompareRow
              label="Resource entropy"
              baseline={comparison.resource_entropy.baseline.toFixed(3)}
              observed={comparison.resource_entropy.observed.toFixed(3)}
              alarming={comparison.resource_entropy.observed > comparison.resource_entropy.baseline * 1.6}
              note="Shannon entropy of the resource access distribution"
            />
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <div className="border-b border-[--color-border-subtle] px-5 py-3">
            <h3 className="text-sm font-semibold">Routine resources</h3>
            <p className="mt-0.5 text-xs text-[--color-ink-muted]">
              The learned access surface for this identity
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5 px-5 py-4">
            {comparison.known_resources.length === 0 ? (
              <p className="text-xs text-[--color-ink-muted]">None recorded.</p>
            ) : (
              comparison.known_resources.map((resource) => (
                <Badge key={resource} className="font-mono text-[10px]">
                  {resource}
                </Badge>
              ))
            )}
          </div>
        </Panel>

        <Panel>
          <div className="border-b border-[--color-border-subtle] px-5 py-3">
            <h3 className="text-sm font-semibold">Novel this window</h3>
            <p className="mt-0.5 text-xs text-[--color-ink-muted]">
              Never seen in the learned access set — the raw material of the resource vector
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5 px-5 py-4">
            {comparison.novel_resources.length === 0 ? (
              <p className="text-xs text-[--color-ink-muted]">
                Nothing novel — every resource touched was already in the baseline.
              </p>
            ) : (
              comparison.novel_resources.map((resource) => (
                <Badge key={resource} className="border-orange-500/30 bg-orange-500/10 font-mono text-[10px] text-orange-300">
                  {resource}
                </Badge>
              ))
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <FactPanel
          title="Known countries"
          items={(baseline.known_countries as string[]) ?? []}
          empty="No geography learned yet."
        />
        <FactPanel
          title="Known devices"
          items={(baseline.known_devices as string[]) ?? []}
          empty="No device fingerprints recorded."
        />
        <Panel>
          <div className="border-b border-[--color-border-subtle] px-5 py-3">
            <h3 className="text-sm font-semibold">Learned statistics</h3>
          </div>
          <dl className="space-y-2 px-5 py-4 text-xs">
            <Fact label="Mean daily events" value={String(baseline.avg_daily_events)} />
            <Fact label="Std deviation" value={String(baseline.stddev_daily_events)} />
            <Fact label="Resource entropy" value={String(baseline.resource_entropy)} />
            <Fact label="Off-hours ratio" value={percent((baseline.off_hours_ratio as number) * 100, 2)} />
            <Fact
              label="Sensitivity ceiling"
              value={`Tier ${baseline.typical_max_sensitivity} · ${SENSITIVITY_LABELS[baseline.typical_max_sensitivity as number] ?? '?'}`}
            />
          </dl>
        </Panel>
      </div>
    </div>
  )
}

function CompareRow({
  label,
  baseline,
  observed,
  alarming,
  note,
}: {
  label: string
  baseline: string
  observed: string
  alarming: boolean
  note: string
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3">
      <div className="min-w-44 flex-1">
        <p className="text-xs font-medium">{label}</p>
        <p className="text-[10px] text-[--color-ink-faint]">{note}</p>
      </div>
      <div className="text-right">
        <p className="text-[10px] text-[--color-ink-faint]">Baseline</p>
        <p className="numeric text-xs text-[--color-ink-muted]">{baseline}</p>
      </div>
      <svg className="size-4 shrink-0 text-[--color-ink-faint]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M5 12h14M13 6l6 6-6 6" />
      </svg>
      <div className="min-w-24 text-right">
        <p className="text-[10px] text-[--color-ink-faint]">Observed</p>
        <p className={cn('numeric text-xs font-medium', alarming ? 'text-rose-300' : 'text-[--color-ink]')}>
          {observed}
        </p>
      </div>
    </div>
  )
}

function FactPanel({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <Panel>
      <div className="border-b border-[--color-border-subtle] px-5 py-3">
        <h3 className="text-sm font-semibold">{title}</h3>
      </div>
      <div className="flex flex-wrap gap-1.5 px-5 py-4">
        {items.length === 0 ? (
          <p className="text-xs text-[--color-ink-muted]">{empty}</p>
        ) : (
          items.map((item) => (
            <Badge key={item} className="font-mono text-[10px]">
              {item}
            </Badge>
          ))
        )}
      </div>
    </Panel>
  )
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-[--color-ink-muted]">{label}</dt>
      <dd className="numeric">{value}</dd>
    </div>
  )
}

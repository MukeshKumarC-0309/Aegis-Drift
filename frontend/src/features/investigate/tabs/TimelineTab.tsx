import { useMemo, useState } from 'react'
import type { Investigation, TimelinePoint } from '@/types/api'
import { Badge, Button, EmptyState } from '@/components/ui'
import { absoluteTime, riskColor, SENSITIVITY_LABELS, titleise, VECTOR_LABELS } from '@/lib/format'
import { cn } from '@/lib/utils'

type Filter = 'all' | 'anomalous' | 'damped' | 'tamper'

export function TimelineTab({ data }: { data: Investigation }) {
  const [filter, setFilter] = useState<Filter>('anomalous')
  const [selected, setSelected] = useState<TimelinePoint | null>(null)

  const filtered = useMemo(() => {
    const points = [...data.timeline].reverse()
    switch (filter) {
      case 'anomalous':
        return points.filter((p) => p.raw_event_score >= 40)
      case 'damped':
        return points.filter((p) => p.is_damped)
      case 'tamper':
        return points.filter((p) => p.anti_tamper)
      default:
        return points
    }
  }, [data.timeline, filter])

  const counts = useMemo(
    () => ({
      all: data.timeline.length,
      anomalous: data.timeline.filter((p) => p.raw_event_score >= 40).length,
      damped: data.timeline.filter((p) => p.is_damped).length,
      tamper: data.timeline.filter((p) => p.anti_tamper).length,
    }),
    [data.timeline],
  )

  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {(
            [
              ['anomalous', 'Anomalous'],
              ['all', 'All events'],
              ['damped', 'Context damped'],
              ['tamper', 'Anti-tamper'],
            ] as [Filter, string][]
          ).map(([id, label]) => (
            <Button
              key={id}
              size="sm"
              variant={filter === id ? 'primary' : 'subtle'}
              onClick={() => setFilter(id)}
            >
              {label}
              <span className="numeric ml-1 opacity-60">{counts[id]}</span>
            </Button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            title="Nothing matches this filter"
            description={
              filter === 'anomalous'
                ? 'No event in this window scored above 40 — the identity is behaving normally.'
                : 'Try a different filter.'
            }
          />
        ) : (
          <ol className="relative space-y-1 border-l border-[--color-border-subtle] pl-5">
            {filtered.map((point) => {
              const isSelected = selected?.event_id === point.event_id
              return (
                <li key={point.event_id} className="relative">
                  <span
                    className="absolute top-3.5 -left-[1.4rem] size-2 rounded-full ring-2 ring-[--color-surface]"
                    style={{ backgroundColor: point.anti_tamper ? '#f43f5e' : riskColor(point.raw_event_score) }}
                  />
                  <button
                    onClick={() => setSelected(isSelected ? null : point)}
                    className={cn(
                      'w-full rounded-lg border px-3 py-2.5 text-left transition-colors',
                      isSelected
                        ? 'border-cyan-500/40 bg-cyan-500/8'
                        : 'border-transparent hover:border-[--color-border] hover:bg-white/[0.02]',
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="numeric text-[11px] text-[--color-ink-faint]">
                        {absoluteTime(point.timestamp, 'dd MMM HH:mm')}
                      </span>
                      <span className="font-mono text-xs font-medium">{point.action}</span>
                      <span className="truncate font-mono text-[11px] text-[--color-ink-muted]">
                        {point.resource}
                      </span>
                      <span className="ml-auto flex shrink-0 items-center gap-1.5">
                        {point.anti_tamper && (
                          <Badge className="border-rose-500/40 bg-rose-500/10 py-0 text-[9px] text-rose-300">
                            tamper
                          </Badge>
                        )}
                        {point.is_damped && (
                          <Badge className="border-indigo-500/30 bg-indigo-500/10 py-0 text-[9px] text-indigo-300">
                            damped
                          </Badge>
                        )}
                        <span
                          className="numeric text-xs font-semibold"
                          style={{ color: riskColor(point.raw_event_score) }}
                        >
                          {point.raw_event_score.toFixed(0)}
                        </span>
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-2 text-[10px] text-[--color-ink-faint]">
                      <span>Tier {point.sensitivity}</span>
                      <span>·</span>
                      <span>cumulative {point.cumulative_risk.toFixed(1)}</span>
                      <span>·</span>
                      <span>{titleise(point.state)}</span>
                      {point.matched_rules.length > 0 && (
                        <>
                          <span>·</span>
                          <span className="text-amber-400/80">{point.matched_rules.length} rule(s)</span>
                        </>
                      )}
                    </div>
                  </button>
                </li>
              )
            })}
          </ol>
        )}
      </div>

      <aside className="lg:sticky lg:top-20 lg:self-start">
        {selected ? (
          <EventDetail point={selected} />
        ) : (
          <div className="rounded-lg border border-dashed border-[--color-border] px-4 py-10 text-center">
            <p className="text-xs text-[--color-ink-muted]">
              Select an event to see its full vector breakdown and why it scored the way it did.
            </p>
          </div>
        )}
      </aside>
    </div>
  )
}

function EventDetail({ point }: { point: TimelinePoint }) {
  const vectors = Object.entries(point.vectors)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])

  return (
    <div className="rounded-lg border border-[--color-border] bg-[--color-surface-raised] p-4">
      <p className="text-[10px] tracking-wider text-[--color-ink-faint] uppercase">Event detail</p>
      <p className="mt-1 font-mono text-sm font-medium">{point.action}</p>
      <p className="font-mono text-xs break-all text-[--color-ink-muted]">{point.resource}</p>

      <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 border-t border-[--color-border-subtle] pt-3">
        <Row label="Occurred" value={absoluteTime(point.timestamp, 'dd MMM yyyy HH:mm:ss')} span />
        <Row label="Type" value={titleise(point.event_type)} />
        <Row label="Sensitivity" value={`T${point.sensitivity} · ${SENSITIVITY_LABELS[point.sensitivity]}`} />
        <Row label="Raw score" value={point.raw_event_score.toFixed(1)} />
        <Row label="After damping" value={point.event_score.toFixed(1)} />
        <Row label="Cumulative" value={point.cumulative_risk.toFixed(1)} />
        <Row label="State" value={titleise(point.state)} />
      </dl>

      <div className="mt-4 border-t border-[--color-border-subtle] pt-3">
        <p className="mb-2 text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
          Vector breakdown
        </p>
        {vectors.length === 0 ? (
          <p className="text-xs text-[--color-ink-muted]">No vector fired on this event.</p>
        ) : (
          <ul className="space-y-2">
            {vectors.map(([vector, value]) => (
              <li key={vector}>
                <div className="mb-1 flex items-baseline justify-between text-[11px]">
                  <span className="text-[--color-ink-muted]">{VECTOR_LABELS[vector] ?? vector}</span>
                  <span className="numeric">{value.toFixed(0)}</span>
                </div>
                <div className="h-1 w-full overflow-hidden rounded-full bg-white/8">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${value}%`, backgroundColor: riskColor(value) }}
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {point.matched_rules.length > 0 && (
        <div className="mt-4 border-t border-[--color-border-subtle] pt-3">
          <p className="mb-1.5 text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
            Rules matched
          </p>
          <div className="flex flex-wrap gap-1.5">
            {point.matched_rules.map((rule) => (
              <Badge key={rule} className="border-amber-500/30 bg-amber-500/10 text-amber-300">
                {rule}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {point.damping_reason && (
        <div
          className={cn(
            'mt-4 rounded-lg border px-3 py-2.5 text-[11px] leading-relaxed',
            point.anti_tamper
              ? 'border-rose-500/30 bg-rose-500/8 text-rose-200'
              : 'border-indigo-500/30 bg-indigo-500/8 text-indigo-200',
          )}
        >
          {point.damping_reason}
        </div>
      )}
    </div>
  )
}

function Row({ label, value, span }: { label: string; value: string; span?: boolean }) {
  return (
    <div className={span ? 'col-span-2' : undefined}>
      <dt className="text-[10px] text-[--color-ink-faint]">{label}</dt>
      <dd className="numeric text-xs">{value}</dd>
    </div>
  )
}

import { useEffect, useState } from 'react'
import { useAuditTrail, useHyperparameters, useOperators, useUpdateHyperparameters } from '@/lib/queries'
import { useAuth } from '@/lib/auth'
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Input,
  Panel,
  PanelHeader,
  Skeleton,
  Tabs,
} from '@/components/ui'
import { Pagination } from '@/components/ui/pagination'
import { absoluteTime, percent, VECTOR_LABELS } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { Hyperparameters } from '@/types/api'

export function SettingsPage() {
  const [tab, setTab] = useState<'engine' | 'audit' | 'operators'>('engine')

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-0.5 text-xs text-[--color-ink-muted]">
          Engine tuning, the audit trail and operator administration.
        </p>
      </header>

      <Panel>
        <Tabs
          tabs={[
            { id: 'engine', label: 'Engine tuning' },
            { id: 'audit', label: 'Audit trail' },
            { id: 'operators', label: 'Operators' },
          ]}
          active={tab}
          onChange={setTab}
          className="px-2"
        />
        <div>
          {tab === 'engine' && <EngineTuning />}
          {tab === 'audit' && <AuditTrail />}
          {tab === 'operators' && <Operators />}
        </div>
      </Panel>
    </div>
  )
}

function EngineTuning() {
  const { can } = useAuth()
  const { data, isLoading, error, refetch } = useHyperparameters()
  const update = useUpdateHyperparameters()
  const [draft, setDraft] = useState<Hyperparameters | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    if (data) setDraft(structuredClone(data))
  }, [data])

  if (isLoading) return <Skeleton className="m-4 h-72" />
  if (error) return <ErrorState error={error} retry={() => void refetch()} />
  if (!draft || !data) return null

  const dirty = JSON.stringify(draft) !== JSON.stringify(data)
  const ordered =
    draft.threshold_early_drift < draft.threshold_escalating &&
    draft.threshold_escalating < draft.threshold_critical

  const weightTotal = Object.values(draft.vector_weights).reduce((a, b) => a + b, 0)

  const save = async (recompute: boolean) => {
    setMessage(null)
    try {
      await update.mutateAsync({ ...draft, recompute })
      setMessage(
        recompute
          ? 'Engine retuned and every identity re-scored.'
          : 'Engine retuned. Existing scores are unchanged until the next scoring cycle.',
      )
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Update failed.')
    }
  }

  return (
    <div className="space-y-5 p-5">
      {!can('admin') && (
        <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-4 py-2.5 text-xs text-amber-200/80">
          Engine tuning requires the <strong>admin</strong> role. These values are read-only for you.
        </div>
      )}

      <section>
        <h3 className="text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Risk accumulator
        </h3>
        <p className="mt-1 mb-3 max-w-2xl text-xs leading-relaxed text-[--color-ink-muted]">
          Risk decays continuously between events. The half-life sets how long a single anomaly keeps
          influencing the score: shorter forgets faster and favours bursts, longer is more sensitive
          to genuinely slow drift but holds a grudge.
        </p>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Slider
            label="Decay half-life"
            unit="hours"
            min={1}
            max={168}
            step={1}
            value={draft.decay_halflife_hours}
            disabled={!can('admin')}
            onChange={(v) => setDraft({ ...draft, decay_halflife_hours: v })}
            hint="Risk halves over this period of inactivity."
          />
          <Slider
            label="Normal threshold"
            min={5}
            max={70}
            step={1}
            value={draft.normal_threshold}
            disabled={!can('admin')}
            onChange={(v) => setDraft({ ...draft, normal_threshold: v })}
            hint="Events at or below this do not accumulate risk at all."
          />
          <Slider
            label="Synergy trigger"
            min={20}
            max={90}
            step={1}
            value={draft.synergy_elevated_at}
            disabled={!can('admin')}
            onChange={(v) => setDraft({ ...draft, synergy_elevated_at: v })}
            hint="A vector counts as elevated above this, and simultaneous elevated vectors multiply."
          />
        </div>
      </section>

      <section>
        <h3 className="text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          State thresholds
        </h3>
        <p className="mt-1 mb-3 text-xs text-[--color-ink-muted]">
          Must stay strictly ordered. The API rejects an out-of-order set rather than silently
          reordering it.
        </p>
        <div className="grid gap-4 sm:grid-cols-3">
          <Slider
            label="Early drift"
            min={5}
            max={90}
            step={1}
            value={draft.threshold_early_drift}
            disabled={!can('admin')}
            onChange={(v) => setDraft({ ...draft, threshold_early_drift: v })}
            color="var(--color-drift)"
          />
          <Slider
            label="Escalating"
            min={10}
            max={95}
            step={1}
            value={draft.threshold_escalating}
            disabled={!can('admin')}
            onChange={(v) => setDraft({ ...draft, threshold_escalating: v })}
            color="var(--color-escalating)"
          />
          <Slider
            label="Critical"
            min={20}
            max={100}
            step={1}
            value={draft.threshold_critical}
            disabled={!can('admin')}
            onChange={(v) => setDraft({ ...draft, threshold_critical: v })}
            color="var(--color-critical)"
          />
        </div>
        {!ordered && (
          <p className="mt-2 text-xs text-rose-300">
            Thresholds must satisfy early drift &lt; escalating &lt; critical.
          </p>
        )}
      </section>

      <section>
        <h3 className="text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Vector weights
        </h3>
        <p className="mt-1 mb-3 text-xs text-[--color-ink-muted]">
          Relative influence of each behavioural dimension. Weights are renormalised to sum to 1, so
          adjusting one rebalances the rest rather than inflating every score.
        </p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Object.entries(draft.vector_weights).map(([vector, weight]) => (
            <div key={vector}>
              <div className="mb-1 flex items-baseline justify-between">
                <span className="text-xs text-[--color-ink-muted]">{VECTOR_LABELS[vector] ?? vector}</span>
                <span className="numeric text-xs">{percent((weight / weightTotal) * 100, 1)}</span>
              </div>
              <input
                type="range"
                min={0}
                max={0.5}
                step={0.01}
                value={weight}
                disabled={!can('admin')}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    vector_weights: { ...draft.vector_weights, [vector]: Number(e.target.value) },
                  })
                }
                className="w-full accent-cyan-400 disabled:opacity-50"
              />
            </div>
          ))}
        </div>
      </section>

      {message && (
        <div className="rounded-lg border border-[--color-border] bg-[--color-surface-raised] px-4 py-2.5 text-xs text-[--color-ink-muted]">
          {message}
        </div>
      )}

      {can('admin') && (
        <div className="flex flex-wrap items-center gap-2 border-t border-[--color-border-subtle] pt-4">
          <Button
            variant="primary"
            disabled={!dirty || !ordered}
            loading={update.isPending}
            onClick={() => void save(true)}
          >
            Save and re-score the fleet
          </Button>
          <Button disabled={!dirty || !ordered} onClick={() => void save(false)}>
            Save without re-scoring
          </Button>
          {dirty && (
            <Button variant="ghost" onClick={() => setDraft(structuredClone(data))}>
              Discard changes
            </Button>
          )}
        </div>
      )}
    </div>
  )
}

function Slider({
  label,
  unit,
  min,
  max,
  step,
  value,
  onChange,
  hint,
  color,
  disabled,
}: {
  label: string
  unit?: string
  min: number
  max: number
  step: number
  value: number
  onChange: (value: number) => void
  hint?: string
  color?: string
  disabled?: boolean
}) {
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-xs font-medium">{label}</span>
        <span className="numeric text-xs" style={color ? { color } : undefined}>
          {value}
          {unit && <span className="ml-1 text-[--color-ink-faint]">{unit}</span>}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full accent-cyan-400 disabled:opacity-50"
      />
      {hint && <p className="mt-1 text-[10px] leading-relaxed text-[--color-ink-faint]">{hint}</p>}
    </div>
  )
}

function AuditTrail() {
  const [page, setPage] = useState(1)
  const [action, setAction] = useState('')
  const { data, isLoading, error, refetch } = useAuditTrail({
    page,
    page_size: 30,
    action: action || undefined,
  })

  return (
    <div>
      <div className="border-b border-[--color-border-subtle] p-3">
        <Input
          value={action}
          onChange={(e) => { setAction(e.target.value); setPage(1) }}
          placeholder="Filter by action, e.g. response, rule, context…"
          className="max-w-sm"
        />
      </div>

      {isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 10 }).map((_, i) => (
            <Skeleton key={i} className="h-10" />
          ))}
        </div>
      ) : error ? (
        <ErrorState error={error} retry={() => void refetch()} />
      ) : !data?.items.length ? (
        <EmptyState title="No audit entries" description="Nothing matches this filter." />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[--color-border-subtle] text-left text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                  <th className="px-5 py-2.5 font-medium">When</th>
                  <th className="py-2.5 font-medium">Actor</th>
                  <th className="py-2.5 font-medium">Action</th>
                  <th className="py-2.5 font-medium">Target</th>
                  <th className="py-2.5 font-medium">Outcome</th>
                  <th className="px-5 py-2.5 font-medium">Request</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[--color-border-subtle]">
                {data.items.map((entry) => (
                  <tr key={entry.id} className="hover:bg-white/[0.02]">
                    <td className="numeric px-5 py-2 text-[11px] whitespace-nowrap text-[--color-ink-muted]">
                      {absoluteTime(entry.created_at, 'dd MMM HH:mm:ss')}
                    </td>
                    <td className="py-2 text-xs">{entry.actor_email}</td>
                    <td className="py-2 font-mono text-[11px] text-cyan-300">{entry.action}</td>
                    <td className="py-2 font-mono text-[11px] text-[--color-ink-muted]">
                      {entry.target_type}
                      {entry.target_id && `:${entry.target_id.slice(0, 14)}`}
                    </td>
                    <td className="py-2">
                      <Badge
                        className={cn(
                          'py-0 text-[9px]',
                          entry.outcome === 'SUCCESS'
                            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                            : 'border-rose-500/30 bg-rose-500/10 text-rose-300',
                        )}
                      >
                        {entry.outcome}
                      </Badge>
                    </td>
                    <td className="px-5 py-2 font-mono text-[10px] text-[--color-ink-faint]">
                      {entry.request_id ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination meta={data.meta} onPage={setPage} />
        </>
      )}
    </div>
  )
}

function Operators() {
  const { can, user } = useAuth()
  const { data, isLoading, error, refetch } = useOperators()

  if (!can('admin')) {
    return (
      <EmptyState
        title="Administrator access required"
        description="Operator administration is restricted to the admin role."
      />
    )
  }
  if (isLoading) return <Skeleton className="m-4 h-48" />
  if (error) return <ErrorState error={error} retry={() => void refetch()} />

  return (
    <div>
      <PanelHeader title="Console operators" subtitle={`${data?.length ?? 0} accounts`} />
      <ul className="divide-y divide-[--color-border-subtle]">
        {(data ?? []).map((operator) => (
          <li key={operator.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
            <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-slate-600 to-slate-800 text-xs font-semibold">
              {operator.full_name.charAt(0)}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <p className="text-xs font-medium">{operator.full_name}</p>
                {operator.id === user?.id && <Badge className="py-0 text-[9px]">you</Badge>}
              </div>
              <p className="truncate text-[11px] text-[--color-ink-faint]">{operator.email}</p>
            </div>
            <Badge className="shrink-0 py-0 text-[10px] capitalize">{operator.role}</Badge>
            <Badge
              className={cn(
                'shrink-0 py-0 text-[9px]',
                operator.is_active
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : 'border-slate-500/30 bg-slate-500/10 text-slate-400',
              )}
            >
              {operator.is_active ? 'active' : 'disabled'}
            </Badge>
            <span className="w-32 shrink-0 text-right text-[10px] text-[--color-ink-faint]">
              {operator.last_login_at ? `last in ${absoluteTime(operator.last_login_at, 'dd MMM HH:mm')}` : 'never signed in'}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

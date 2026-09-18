import type { Investigation } from '@/types/api'
import { Badge } from '@/components/ui'
import { cn } from '@/lib/utils'
import { absoluteTime, percent, relativeTime } from '@/lib/format'

const FINDING_STYLE: Record<string, string> = {
  CRITICAL: 'border-rose-500/30 bg-rose-500/8',
  HIGH: 'border-orange-500/30 bg-orange-500/8',
  MEDIUM: 'border-amber-500/30 bg-amber-500/8',
  LOW: 'border-slate-500/30 bg-slate-500/8',
}

const FINDING_TEXT: Record<string, string> = {
  CRITICAL: 'text-rose-300',
  HIGH: 'text-orange-300',
  MEDIUM: 'text-amber-300',
  LOW: 'text-slate-300',
}

/** Renders the engine's markdown-ish narrative without pulling in a markdown lib. */
function Narrative({ text }: { text: string }) {
  const blocks = text.split('\n\n')
  return (
    <div className="space-y-3 text-sm leading-relaxed text-[--color-ink-muted]">
      {blocks.map((block, i) => {
        if (block.trim().startsWith('- ')) {
          return (
            <ul key={i} className="space-y-1.5 pl-1">
              {block
                .split('\n')
                .filter((line) => line.trim().startsWith('- '))
                .map((line, j) => (
                  <li key={j} className="flex gap-2">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-[--color-ink-faint]" />
                    <span dangerouslySetInnerHTML={{ __html: inline(line.replace(/^- /, '')) }} />
                  </li>
                ))}
            </ul>
          )
        }
        const [first, ...rest] = block.split('\n')
        return (
          <p key={i}>
            <span dangerouslySetInnerHTML={{ __html: inline(first) }} />
            {rest.length > 0 && (
              <span className="block" dangerouslySetInnerHTML={{ __html: inline(rest.join(' ')) }} />
            )}
          </p>
        )
      })}
    </div>
  )
}

/**
 * Bold/italic/code only. The input is generated server-side from our own engine,
 * never from user input, and every tag we emit is one of these three.
 */
function inline(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="font-semibold text-[--color-ink]">$1</strong>')
    .replace(/`(.+?)`/g, '<code class="rounded bg-white/8 px-1 py-0.5 font-mono text-[11px]">$1</code>')
    .replace(/_(.+?)_/g, '<em>$1</em>')
}

export function OverviewTab({ data }: { data: Investigation }) {
  const { explanation } = data
  const peer = explanation.peer_comparison

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <div className="space-y-6 lg:col-span-2">
        <section>
          <h3 className="mb-3 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Analyst brief
          </h3>
          <Narrative text={explanation.narrative} />
        </section>

        <section>
          <h3 className="mb-3 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Findings ({explanation.key_findings.length})
          </h3>
          {explanation.key_findings.length === 0 ? (
            <p className="text-sm text-[--color-ink-muted]">
              No material findings — behaviour is inside the learned envelope.
            </p>
          ) : (
            <ul className="space-y-2">
              {explanation.key_findings.map((finding, i) => (
                <li
                  key={i}
                  className={cn('rounded-lg border px-4 py-3', FINDING_STYLE[finding.severity] ?? FINDING_STYLE.LOW)}
                >
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-sm font-medium text-[--color-ink]">{finding.title}</p>
                    <span
                      className={cn(
                        'shrink-0 text-[10px] font-semibold tracking-wider uppercase',
                        FINDING_TEXT[finding.severity] ?? FINDING_TEXT.LOW,
                      )}
                    >
                      {finding.severity}
                    </span>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-[--color-ink-muted]">{finding.detail}</p>
                </li>
              ))}
            </ul>
          )}
        </section>

        {explanation.counter_evidence.length > 0 && (
          <section>
            <h3 className="mb-2 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
              Considerations against this verdict
            </h3>
            <p className="mb-3 text-xs text-[--color-ink-faint]">
              Stated explicitly so the tool argues both sides rather than only prosecuting.
            </p>
            <ul className="space-y-1.5">
              {explanation.counter_evidence.map((note, i) => (
                <li key={i} className="flex gap-2 text-xs leading-relaxed text-[--color-ink-muted]">
                  <span className="mt-1.5 size-1 shrink-0 rounded-full bg-indigo-400" />
                  {note}
                </li>
              ))}
            </ul>
          </section>
        )}

        <section>
          <h3 className="mb-3 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Contributing events
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[--color-border-subtle] text-left text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                  <th className="pb-2 font-medium">When</th>
                  <th className="pb-2 font-medium">Action</th>
                  <th className="pb-2 font-medium">Resource</th>
                  <th className="pb-2 font-medium">Tier</th>
                  <th className="pb-2 text-right font-medium">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[--color-border-subtle]">
                {explanation.contributing_events.map((event) => (
                  <tr key={event.event_id} className="hover:bg-white/[0.02]">
                    <td className="py-2 whitespace-nowrap text-[--color-ink-muted]">
                      {absoluteTime(event.timestamp, 'dd MMM HH:mm')}
                    </td>
                    <td className="py-2 font-mono text-[11px]">{event.action}</td>
                    <td className="max-w-[16rem] truncate py-2 font-mono text-[11px] text-[--color-ink-muted]" title={event.resource}>
                      {event.resource}
                    </td>
                    <td className="py-2">
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[10px]',
                          event.sensitivity >= 5
                            ? 'bg-rose-500/15 text-rose-300'
                            : event.sensitivity >= 4
                              ? 'bg-orange-500/15 text-orange-300'
                              : 'bg-white/8 text-[--color-ink-muted]',
                        )}
                      >
                        T{event.sensitivity}
                      </span>
                    </td>
                    <td className="py-2 text-right">
                      <span className="numeric font-medium">{event.raw_score.toFixed(0)}</span>
                      {event.is_damped && (
                        <span className="numeric ml-1 text-indigo-300">→{event.damped_score.toFixed(0)}</span>
                      )}
                      {event.anti_tamper && <span className="ml-1.5 text-rose-400">⚠</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* ---------------------------------------------------------- sidebar */}
      <div className="space-y-5">
        <section>
          <h3 className="mb-2 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Recommended response
          </h3>
          {explanation.recommended_actions.length === 0 ? (
            <p className="text-xs text-[--color-ink-muted]">No action required.</p>
          ) : (
            <ol className="space-y-2">
              {explanation.recommended_actions.map((action, i) => (
                <li key={i} className="rounded-lg border border-[--color-border-subtle] bg-[--color-surface-raised] px-3 py-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-xs font-medium">{action.label}</p>
                    <Badge
                      className={cn(
                        'shrink-0 py-0 text-[9px]',
                        action.urgency === 'IMMEDIATE'
                          ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                          : action.urgency === 'HIGH'
                            ? 'border-orange-500/30 bg-orange-500/10 text-orange-300'
                            : '',
                      )}
                    >
                      {action.urgency}
                    </Badge>
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-[--color-ink-muted]">{action.rationale}</p>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section>
          <h3 className="mb-2 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Peer cohort
          </h3>
          {peer.available ? (
            <div className="rounded-lg border border-[--color-border-subtle] bg-[--color-surface-raised] px-3 py-3">
              <p className="font-mono text-[11px] text-[--color-ink-faint]">{peer.cohort}</p>
              <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-2">
                <Metric label="Cohort mean" value={peer.cohort_mean_risk?.toFixed(1) ?? '—'} />
                <Metric label="This identity" value={peer.identity_risk?.toFixed(1) ?? '—'} />
                <Metric
                  label="Z-score"
                  value={peer.z_score !== undefined ? `${peer.z_score > 0 ? '+' : ''}${peer.z_score.toFixed(2)}σ` : '—'}
                />
                <Metric label="Percentile" value={peer.percentile !== undefined ? `${peer.percentile}th` : '—'} />
              </div>
              <p className="mt-2.5 text-[11px] leading-relaxed text-[--color-ink-muted]">{peer.interpretation}</p>
            </div>
          ) : (
            <p className="text-xs text-[--color-ink-muted]">{peer.note}</p>
          )}
        </section>

        <section>
          <h3 className="mb-2 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Business context
          </h3>
          {data.contexts.length === 0 ? (
            <p className="text-xs leading-relaxed text-[--color-ink-muted]">
              No context records exist. Nothing authorises the observed activity.
            </p>
          ) : (
            <ul className="space-y-2">
              {data.contexts.map((context) => (
                <li
                  key={context.id}
                  className={cn(
                    'rounded-lg border px-3 py-2.5',
                    context.currently_covering
                      ? 'border-indigo-500/30 bg-indigo-500/8'
                      : 'border-[--color-border-subtle] bg-[--color-surface-raised]',
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-xs font-medium">{context.title}</p>
                    <Badge className="shrink-0 py-0 text-[9px]">×{context.damping_factor.toFixed(2)}</Badge>
                  </div>
                  <p className="mt-0.5 font-mono text-[10px] text-[--color-ink-faint]">
                    {context.ticket_reference ?? context.id}
                  </p>
                  <p className="mt-1 text-[11px] text-[--color-ink-muted]">
                    {context.currently_covering ? 'Currently covering' : 'Window lapsed'} · approved by{' '}
                    {context.approved_by}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>

        {data.matched_rules.length > 0 && (
          <section>
            <h3 className="mb-2 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
              Rules matched
            </h3>
            <ul className="space-y-1.5">
              {data.matched_rules.map((rule) => (
                <li key={rule.id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="truncate text-[--color-ink-muted]" title={rule.name}>
                    {rule.name}
                  </span>
                  <span className="numeric shrink-0 text-[--color-ink-faint]">+{rule.risk_boost}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {data.alerts.length > 0 && (
          <section>
            <h3 className="mb-2 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
              Alert history
            </h3>
            <ul className="space-y-1.5">
              {data.alerts.slice(0, 5).map((alert) => (
                <li key={alert.id} className="text-xs">
                  <p className="truncate text-[--color-ink-muted]">{alert.title}</p>
                  <p className="text-[10px] text-[--color-ink-faint]">
                    {alert.status} · {relativeTime(alert.created_at)}
                    {alert.occurrence_count > 1 && ` · ×${alert.occurrence_count}`}
                  </p>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section>
          <h3 className="mb-2 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
            Baseline quality
          </h3>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between">
              <span className="text-[--color-ink-muted]">Maturity</span>
              <span className="numeric">
                {percent((explanation.baseline_comparison.baseline_maturity ?? 0) * 100)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[--color-ink-muted]">Sample size</span>
              <span className="numeric">{explanation.baseline_comparison.baseline_sample_size} events</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[10px] text-[--color-ink-faint]">{label}</p>
      <p className="numeric text-sm font-medium">{value}</p>
    </div>
  )
}

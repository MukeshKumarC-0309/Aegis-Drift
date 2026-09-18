import type { Investigation } from '@/types/api'
import { useMitreCoverage } from '@/lib/queries'
import { Badge, EmptyState, Panel, Skeleton } from '@/components/ui'
import { cn } from '@/lib/utils'

export function MitreTab({ data }: { data: Investigation }) {
  const { data: coverage, isLoading } = useMitreCoverage()
  const observed = new Set(data.explanation.mitre_techniques.map((t) => t.id))

  return (
    <div className="space-y-5">
      <section>
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Techniques evidenced for this identity
        </h3>
        <p className="mb-3 text-xs text-[--color-ink-muted]">
          Each mapping cites the specific events that support it. Confidence scales with how
          anomalous those events were.
        </p>

        {data.explanation.mitre_techniques.length === 0 ? (
          <EmptyState
            title="No techniques evidenced"
            description="Nothing in this window matched an ATT&CK technique."
          />
        ) : (
          <ul className="grid gap-3 md:grid-cols-2">
            {data.explanation.mitre_techniques.map((technique) => (
              <li key={technique.id} className="rounded-lg border border-[--color-border-subtle] bg-[--color-surface-raised] p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-mono text-xs font-semibold text-cyan-300">{technique.id}</p>
                    <p className="mt-0.5 text-sm font-medium">{technique.name}</p>
                  </div>
                  <Badge className="shrink-0">{technique.tactic}</Badge>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-[--color-ink-muted]">{technique.description}</p>

                <div className="mt-3 flex items-center gap-2">
                  <div className="h-1 flex-1 overflow-hidden rounded-full bg-white/8">
                    <div
                      className="h-full rounded-full bg-cyan-400"
                      style={{ width: `${technique.confidence}%` }}
                    />
                  </div>
                  <span className="numeric text-[10px] text-[--color-ink-faint]">
                    {technique.confidence}% confidence
                  </span>
                </div>

                {technique.evidence.length > 0 && (
                  <div className="mt-3 border-t border-[--color-border-subtle] pt-2.5">
                    <p className="mb-1 text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                      Evidence
                    </p>
                    <ul className="space-y-0.5">
                      {technique.evidence.map((item, i) => (
                        <li key={i} className="font-mono text-[10px] text-[--color-ink-muted]">
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Fleet-wide ATT&CK coverage
        </h3>
        <p className="mb-3 text-xs text-[--color-ink-muted]">
          Techniques observed anywhere in the estate. Highlighted cells are evidenced for this identity.
        </p>

        {isLoading ? (
          <Skeleton className="h-64" />
        ) : (
          <Panel>
            <div className="overflow-x-auto">
              <div className="flex min-w-max gap-2 p-4">
                {coverage?.matrix.map((column) => (
                  <div key={column.tactic} className="w-40 shrink-0">
                    <div className="mb-2 border-b border-[--color-border-subtle] pb-1.5">
                      <p className="truncate text-[11px] font-semibold" title={column.tactic}>
                        {column.tactic}
                      </p>
                      <p className="numeric text-[10px] text-[--color-ink-faint]">
                        {column.observed}/{column.total}
                      </p>
                    </div>
                    <div className="space-y-1">
                      {column.techniques.map((technique) => {
                        const forThisIdentity = observed.has(technique.id)
                        return (
                          <div
                            key={technique.id}
                            title={`${technique.id} — ${technique.name}\n${technique.description}`}
                            className={cn(
                              'rounded border px-2 py-1.5 transition-colors',
                              forThisIdentity
                                ? 'border-rose-500/40 bg-rose-500/12'
                                : technique.observed
                                  ? 'border-amber-500/25 bg-amber-500/8'
                                  : 'border-[--color-border-subtle] bg-white/[0.02]',
                            )}
                          >
                            <p
                              className={cn(
                                'font-mono text-[9px]',
                                forThisIdentity
                                  ? 'text-rose-300'
                                  : technique.observed
                                    ? 'text-amber-300'
                                    : 'text-[--color-ink-faint]',
                              )}
                            >
                              {technique.id}
                            </p>
                            <p
                              className={cn(
                                'truncate text-[10px]',
                                technique.observed ? 'text-[--color-ink]' : 'text-[--color-ink-faint]',
                              )}
                            >
                              {technique.name}
                            </p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-4 border-t border-[--color-border-subtle] px-4 py-2.5 text-[10px] text-[--color-ink-muted]">
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded border border-rose-500/40 bg-rose-500/12" /> this identity
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded border border-amber-500/25 bg-amber-500/8" /> elsewhere in the estate
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded border border-[--color-border-subtle]" /> not observed
              </span>
              <span className="ml-auto">
                {coverage?.observed_count}/{coverage?.catalog_size} techniques ·{' '}
                {coverage?.coverage_percentage}% coverage
              </span>
            </div>
          </Panel>
        )}
      </section>
    </div>
  )
}

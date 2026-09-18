import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useCaseStats, useCases } from '@/lib/queries'
import { Badge, EmptyState, ErrorState, Panel, Select, Skeleton, Stat } from '@/components/ui'
import { Pagination } from '@/components/ui/pagination'
import { absoluteTime, relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { Case } from '@/types/api'

const STATUS_STYLE: Record<string, string> = {
  NEW: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300',
  IN_PROGRESS: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  PENDING_INPUT: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-300',
  CONTAINED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  RESOLVED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  CLOSED: 'border-slate-500/30 bg-slate-500/10 text-slate-300',
}

const PRIORITY_STYLE: Record<string, string> = {
  P1: 'border-rose-500/40 bg-rose-500/12 text-rose-300',
  P2: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
  P3: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  P4: 'border-slate-500/30 bg-slate-500/10 text-slate-300',
}

export function CasesPage() {
  const [status, setStatus] = useState('')
  const [priority, setPriority] = useState('')
  const [page, setPage] = useState(1)

  const { data, isLoading, error, refetch } = useCases({
    page,
    page_size: 20,
    status_filter: status || undefined,
    priority: priority || undefined,
  })
  const { data: stats } = useCaseStats()
  const s = stats as Record<string, number> | undefined

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Cases</h1>
        <p className="mt-0.5 text-xs text-[--color-ink-muted]">
          Investigations with an owner, an SLA and an auditable timeline.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Panel className="px-4 py-3">
          <Stat label="Total" value={String(s?.total ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Open" value={String(s?.open ?? 0)} accent="var(--color-drift)" />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Overdue"
            value={String(s?.overdue ?? 0)}
            accent={(s?.overdue ?? 0) > 0 ? 'var(--color-critical)' : undefined}
            sublabel="Past SLA"
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Unassigned" value={String(s?.unassigned ?? 0)} />
        </Panel>
      </div>

      <Panel className="p-3">
        <div className="grid gap-2 sm:grid-cols-3">
          <Select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }}>
            <option value="">All statuses</option>
            {Object.keys(STATUS_STYLE).map((v) => (
              <option key={v} value={v}>
                {titleise(v)}
              </option>
            ))}
          </Select>
          <Select value={priority} onChange={(e) => { setPriority(e.target.value); setPage(1) }}>
            <option value="">All priorities</option>
            {Object.keys(PRIORITY_STYLE).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </Select>
        </div>
      </Panel>

      <Panel>
        {isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-16" />
            ))}
          </div>
        ) : error ? (
          <ErrorState error={error} retry={() => void refetch()} />
        ) : !data?.items.length ? (
          <EmptyState
            title="No cases yet"
            description="Open a case from the triage queue to track an investigation with an owner and an SLA."
          />
        ) : (
          <>
            <ul className="divide-y divide-[--color-border-subtle]">
              {data.items.map((record) => (
                <li key={record.id}>
                  <Link
                    to={`/cases/${record.id}`}
                    className="flex flex-wrap items-center gap-3 px-5 py-3.5 transition-colors hover:bg-white/[0.02]"
                  >
                    <div className="min-w-56 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs text-[--color-ink-faint]">{record.reference}</span>
                        <span className="text-sm font-medium">{record.title}</span>
                      </div>
                      {record.description && (
                        <p className="mt-0.5 truncate text-xs text-[--color-ink-muted]">{record.description}</p>
                      )}
                      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[--color-ink-faint]">
                        <span>Opened {relativeTime(record.created_at)}</span>
                        {record.peak_risk_score > 0 && (
                          <>
                            <span>·</span>
                            <span className="numeric">peak risk {record.peak_risk_score.toFixed(0)}</span>
                          </>
                        )}
                        {record.mitre_techniques.length > 0 && (
                          <>
                            <span>·</span>
                            <span className="font-mono">{record.mitre_techniques.slice(0, 3).join(' ')}</span>
                          </>
                        )}
                      </div>
                    </div>

                    <SlaPill record={record} />

                    <div className="flex shrink-0 items-center gap-1.5">
                      <Badge className={cn('py-0 text-[10px]', PRIORITY_STYLE[record.priority])}>
                        {record.priority}
                      </Badge>
                      <Badge className={cn('py-0 text-[10px]', STATUS_STYLE[record.status])}>
                        {titleise(record.status)}
                      </Badge>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
            <Pagination meta={data.meta} onPage={setPage} />
          </>
        )}
      </Panel>
    </div>
  )
}

function SlaPill({ record }: { record: Case }) {
  if (!record.sla_due_at || record.status === 'CLOSED' || record.status === 'RESOLVED') {
    return <span className="w-28 shrink-0 text-right text-[10px] text-[--color-ink-faint]">—</span>
  }
  const due = new Date(`${record.sla_due_at}Z`).getTime()
  const overdue = due < Date.now()
  return (
    <span
      className={cn(
        'w-28 shrink-0 text-right text-[10px]',
        overdue ? 'font-medium text-rose-300' : 'text-[--color-ink-faint]',
      )}
      title={`SLA due ${absoluteTime(record.sla_due_at)}`}
    >
      {overdue ? 'SLA breached' : `due ${relativeTime(record.sla_due_at).replace(' ago', '')}`}
    </span>
  )
}

import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAddCaseEntry, useCase, useUpdateCase } from '@/lib/queries'
import { useAuth } from '@/lib/auth'
import {
  Badge,
  Button,
  ErrorState,
  Input,
  Panel,
  PanelHeader,
  Select,
  Skeleton,
  Stat,
} from '@/components/ui'
import { SeverityBadge } from '@/features/dashboard/CommandCenter'
import { absoluteTime, compactNumber, relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'

const STATUSES = ['NEW', 'IN_PROGRESS', 'PENDING_INPUT', 'CONTAINED', 'RESOLVED', 'CLOSED']

const ENTRY_ICON: Record<string, string> = {
  CREATED: 'bg-cyan-400',
  STATUS_CHANGE: 'bg-amber-400',
  COMMENT: 'bg-slate-400',
  ACTION: 'bg-indigo-400',
}

export function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>()
  const { can } = useAuth()
  const { data, isLoading, error, refetch } = useCase(caseId)
  const update = useUpdateCase()
  const addEntry = useAddCaseEntry()
  const [comment, setComment] = useState('')

  if (isLoading) return <Skeleton className="h-96" />
  if (error) return <ErrorState error={error} retry={() => void refetch()} />
  if (!data) return null

  const submitComment = async () => {
    if (!comment.trim() || !caseId) return
    await addEntry.mutateAsync({ caseId, body: comment.trim() })
    setComment('')
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-[--color-ink-faint]">
        <Link to="/cases" className="transition-colors hover:text-[--color-ink]">
          Cases
        </Link>
        <span>/</span>
        <span className="font-mono text-[--color-ink]">{data.reference}</span>
      </div>

      <Panel lit>
        <div className="flex flex-wrap items-start gap-4 px-5 py-4">
          <div className="min-w-64 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-lg font-semibold tracking-tight">{data.title}</h1>
              <Badge className="py-0 text-[10px]">{data.priority}</Badge>
              <SeverityBadge severity={data.severity} />
            </div>
            {data.description && (
              <p className="mt-1.5 text-xs leading-relaxed text-[--color-ink-muted]">{data.description}</p>
            )}
            <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
              <Stat label="Opened" value={relativeTime(data.created_at)} />
              <Stat label="Peak risk" value={data.peak_risk_score.toFixed(0)} />
              <Stat label="Blast radius" value={data.blast_radius_score.toFixed(0)} />
              <Stat label="Records at risk" value={compactNumber(data.estimated_records_at_risk)} />
              <Stat
                label="SLA"
                value={
                  data.sla_due_at
                    ? new Date(`${data.sla_due_at}Z`).getTime() < Date.now()
                      ? 'Breached'
                      : relativeTime(data.sla_due_at).replace(' ago', '')
                    : '—'
                }
                accent={
                  data.sla_due_at && new Date(`${data.sla_due_at}Z`).getTime() < Date.now()
                    ? 'var(--color-critical)'
                    : undefined
                }
              />
            </div>
          </div>

          {can('analyst') && (
            <div className="w-44 shrink-0">
              <label className="mb-1.5 block text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                Status
              </label>
              <Select
                value={data.status}
                onChange={(e) => update.mutate({ id: data.id, body: { status: e.target.value } })}
              >
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {titleise(s)}
                  </option>
                ))}
              </Select>
            </div>
          )}
        </div>

        {data.mitre_techniques.length > 0 && (
          <div className="flex flex-wrap gap-1.5 border-t border-[--color-border-subtle] px-5 py-2.5">
            <span className="text-[10px] tracking-wider text-[--color-ink-faint] uppercase">ATT&CK</span>
            {data.mitre_techniques.map((t) => (
              <Badge key={t} className="py-0 font-mono text-[10px]">
                {t}
              </Badge>
            ))}
          </div>
        )}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHeader title="Timeline" subtitle="Every status change, comment and automated note" />

          <ol className="relative space-y-3 px-5 py-4">
            {(data.entries ?? []).map((entry) => (
              <li key={entry.id} className="relative flex gap-3 pl-5">
                <span
                  className={cn(
                    'absolute top-1.5 left-0 size-2 rounded-full',
                    ENTRY_ICON[entry.entry_type] ?? ENTRY_ICON.COMMENT,
                  )}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="text-xs font-medium">{entry.author_label}</span>
                    <Badge className="py-0 text-[9px]">{titleise(entry.entry_type)}</Badge>
                    <span className="text-[10px] text-[--color-ink-faint]">
                      {absoluteTime(entry.created_at)}
                    </span>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-[--color-ink-muted]">{entry.body}</p>
                </div>
              </li>
            ))}
          </ol>

          {can('analyst') && (
            <div className="flex gap-2 border-t border-[--color-border-subtle] px-5 py-3">
              <Input
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    void submitComment()
                  }
                }}
                placeholder="Add a note to the case timeline…"
              />
              <Button
                variant="primary"
                loading={addEntry.isPending}
                disabled={!comment.trim()}
                onClick={() => void submitComment()}
              >
                Post
              </Button>
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHeader title="Linked alerts" subtitle={`${data.alerts?.length ?? 0} alert(s)`} />
          {!data.alerts?.length ? (
            <p className="px-5 py-8 text-center text-xs text-[--color-ink-muted]">No alerts linked.</p>
          ) : (
            <ul className="divide-y divide-[--color-border-subtle]">
              {data.alerts.map((alert) => (
                <li key={alert.id}>
                  <Link
                    to={`/investigate/${alert.identity_id}`}
                    className="block px-5 py-3 transition-colors hover:bg-white/[0.02]"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-xs font-medium">{alert.title}</p>
                      <span className="numeric shrink-0 text-xs">{alert.risk_score.toFixed(0)}</span>
                    </div>
                    <p className="mt-0.5 text-[11px] text-[--color-ink-muted]">{alert.summary}</p>
                    <p className="mt-1 text-[10px] text-[--color-ink-faint]">
                      {titleise(alert.status)} · {relativeTime(alert.created_at)}
                    </p>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}

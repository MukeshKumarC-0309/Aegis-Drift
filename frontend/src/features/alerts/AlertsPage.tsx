import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAlerts, useAlertStats, useAssignAlert, useCreateCase, useUpdateAlert } from '@/lib/queries'
import { useAuth } from '@/lib/auth'
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Field,
  Input,
  Modal,
  Panel,
  Select,
  Skeleton,
  Stat,
} from '@/components/ui'
import { Pagination } from '@/components/ui/pagination'
import { RiskDial, SeverityBadge, StateBadge } from '@/features/dashboard/CommandCenter'
import { relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { Alert } from '@/types/api'

const STATUSES = ['OPEN', 'TRIAGED', 'INVESTIGATING', 'SUPPRESSED', 'FALSE_POSITIVE', 'CONFIRMED_INCIDENT', 'CLOSED']
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export function AlertsPage() {
  const { can } = useAuth()
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [openOnly, setOpenOnly] = useState(true)
  const [unassigned, setUnassigned] = useState(false)
  const [dampedFilter, setDampedFilter] = useState<'' | 'true' | 'false'>('')
  const [page, setPage] = useState(1)
  const [caseFor, setCaseFor] = useState<Alert | null>(null)

  const params = {
    page,
    page_size: 20,
    status: status || undefined,
    severity: severity || undefined,
    open_only: openOnly || undefined,
    unassigned: unassigned || undefined,
    damped: dampedFilter === '' ? undefined : dampedFilter === 'true',
  }

  const { data, isLoading, error, refetch, isFetching } = useAlerts(params)
  const { data: stats } = useAlertStats()
  const assign = useAssignAlert()
  const update = useUpdateAlert()

  const s = stats as Record<string, number> | undefined

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Triage queue</h1>
        <p className="mt-0.5 text-xs text-[--color-ink-muted]">
          Alerts ranked by composite risk. Suppressed alerts are kept visible so damping decisions
          stay auditable rather than silently disappearing.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Panel className="px-4 py-3">
          <Stat label="Total" value={String(s?.total ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Open" value={String(s?.open ?? 0)} accent="var(--color-escalating)" />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Unassigned" value={String(s?.unassigned ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Suppressed" value={String(s?.suppressed ?? 0)} accent="var(--color-suppressed)" />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Anti-tamper"
            value={String(s?.anti_tamper ?? 0)}
            accent={(s?.anti_tamper ?? 0) > 0 ? 'var(--color-critical)' : undefined}
          />
        </Panel>
      </div>

      <Panel className="p-3">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          <Select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }}>
            <option value="">All statuses</option>
            {STATUSES.map((v) => (
              <option key={v} value={v}>
                {titleise(v)}
              </option>
            ))}
          </Select>
          <Select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}>
            <option value="">All severities</option>
            {SEVERITIES.map((v) => (
              <option key={v} value={v}>
                {titleise(v)}
              </option>
            ))}
          </Select>
          <Select value={dampedFilter} onChange={(e) => { setDampedFilter(e.target.value as '' | 'true' | 'false'); setPage(1) }}>
            <option value="">Damped or not</option>
            <option value="true">Context damped</option>
            <option value="false">Not damped</option>
          </Select>
          <Button
            size="sm"
            variant={openOnly ? 'primary' : 'subtle'}
            onClick={() => { setOpenOnly((v) => !v); setPage(1) }}
          >
            Open only
          </Button>
          <Button
            size="sm"
            variant={unassigned ? 'primary' : 'subtle'}
            onClick={() => { setUnassigned((v) => !v); setPage(1) }}
          >
            Unassigned
          </Button>
        </div>
      </Panel>

      <Panel>
        {isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : error ? (
          <ErrorState error={error} retry={() => void refetch()} />
        ) : !data?.items.length ? (
          <EmptyState
            title="Queue is clear"
            description="No alerts match these filters. That is the goal — the value of suppression is that what remains is worth reading."
          />
        ) : (
          <>
            <ul className={cn('divide-y divide-[--color-border-subtle]', isFetching && 'opacity-60')}>
              {data.items.map((alert) => (
                <li key={alert.id} className="flex flex-wrap items-start gap-4 px-5 py-4">
                  <RiskDial score={alert.risk_score} size={42} />

                  <div className="min-w-64 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        to={`/investigate/${alert.identity_id}`}
                        className="text-sm font-medium transition-colors hover:text-cyan-200"
                      >
                        {alert.username ?? alert.identity_id}
                      </Link>
                      <StateBadge state={alert.transition_state} />
                      <SeverityBadge severity={alert.severity} />
                      <Badge className="py-0 text-[9px]">{titleise(alert.status)}</Badge>
                      {alert.anti_tamper_override && (
                        <Badge className="border-rose-500/40 bg-rose-500/10 py-0 text-[9px] text-rose-300">
                          anti-tamper
                        </Badge>
                      )}
                      {alert.context_damped && (
                        <Badge className="border-indigo-500/30 bg-indigo-500/10 py-0 text-[9px] text-indigo-300">
                          damped
                        </Badge>
                      )}
                      {alert.occurrence_count > 1 && (
                        <Badge className="py-0 text-[9px]">×{alert.occurrence_count}</Badge>
                      )}
                    </div>

                    <p className="mt-1 text-xs text-[--color-ink]">{alert.title}</p>
                    <p className="mt-0.5 text-xs leading-relaxed text-[--color-ink-muted]">{alert.summary}</p>

                    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[--color-ink-faint]">
                      <span>{alert.department}</span>
                      <span>·</span>
                      <span>raw {alert.raw_risk_score.toFixed(0)}</span>
                      <span>·</span>
                      <span>{alert.confidence.toFixed(0)}% confidence</span>
                      {alert.mitre_techniques.length > 0 && (
                        <>
                          <span>·</span>
                          <span className="font-mono">{alert.mitre_techniques.slice(0, 4).join(' ')}</span>
                        </>
                      )}
                      <span>·</span>
                      <span>{relativeTime(alert.created_at)}</span>
                    </div>

                    {alert.damping_reason && (
                      <p className="mt-2 rounded border border-indigo-500/20 bg-indigo-500/5 px-2.5 py-1.5 text-[11px] leading-relaxed text-indigo-200/75">
                        {alert.damping_reason}
                      </p>
                    )}
                  </div>

                  {can('analyst') && (
                    <div className="flex shrink-0 flex-col gap-1.5">
                      <Link to={`/investigate/${alert.identity_id}`}>
                        <Button size="sm" variant="primary" className="w-full">
                          Investigate
                        </Button>
                      </Link>
                      {!alert.assigned_to_id && (
                        <Button
                          size="sm"
                          loading={assign.isPending}
                          onClick={() => assign.mutate(alert.id)}
                        >
                          Assign to me
                        </Button>
                      )}
                      <Button size="sm" onClick={() => setCaseFor(alert)}>
                        Open case
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          update.mutate({ id: alert.id, body: { status: 'FALSE_POSITIVE' } })
                        }
                      >
                        False positive
                      </Button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
            <Pagination meta={data.meta} onPage={setPage} />
          </>
        )}
      </Panel>

      <CreateCaseModal alert={caseFor} onClose={() => setCaseFor(null)} />
    </div>
  )
}

function CreateCaseModal({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  const create = useCreateCase()
  const [title, setTitle] = useState('')
  const [priority, setPriority] = useState('P2')
  const [description, setDescription] = useState('')

  const effectiveTitle = title || (alert ? `Investigation: ${alert.username ?? alert.identity_id}` : '')

  const submit = async () => {
    if (!alert) return
    await create.mutateAsync({
      title: effectiveTitle,
      description,
      priority,
      severity: alert.severity,
      primary_identity_id: alert.identity_id,
      alert_ids: [alert.id],
      tags: alert.dominant_vectors,
    })
    setTitle('')
    setDescription('')
    onClose()
  }

  return (
    <Modal
      open={Boolean(alert)}
      onClose={onClose}
      title="Open an investigation case"
      description="Links this alert to a tracked case with an owner and an SLA."
      footer={
        <>
          <Button size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" loading={create.isPending} onClick={() => void submit()}>
            Open case
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Title">
          <Input value={effectiveTitle} onChange={(e) => setTitle(e.target.value)} />
        </Field>
        <Field label="Priority" hint="Sets the SLA: P1 one hour, P2 four hours, P3 one day, P4 three days.">
          <Select value={priority} onChange={(e) => setPriority(e.target.value)}>
            {['P1', 'P2', 'P3', 'P4'].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Description" hint="Optional opening note for the case timeline.">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
      </div>
    </Modal>
  )
}

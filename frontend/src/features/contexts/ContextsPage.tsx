import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useContexts, useCreateContext, useIdentities, useRevokeContext } from '@/lib/queries'
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
import { absoluteTime, percent, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { ContextRecord } from '@/types/api'

const CONTEXT_TYPES = [
  'APPROVED_CHANGE_TICKET',
  'PROJECT_TRANSFER',
  'ON_CALL_ROTATION',
  'MAINTENANCE_WINDOW',
  'TRAVEL_EXEMPTION',
  'ROLE_CHANGE',
  'INCIDENT_RESPONSE',
]

export function ContextsPage() {
  const { can } = useAuth()
  const [page, setPage] = useState(1)
  const [type, setType] = useState('')
  const [activeOnly, setActiveOnly] = useState(true)
  const [creating, setCreating] = useState(false)

  const { data, isLoading, error, refetch } = useContexts({
    page,
    page_size: 20,
    context_type: type || undefined,
    active_only: activeOnly || undefined,
  })
  const revoke = useRevokeContext()

  const records = (data?.items ?? []) as unknown as ContextRecord[]
  const now = Date.now()
  const covering = records.filter(
    (r) => r.is_active && new Date(`${r.valid_until}Z`).getTime() > now && new Date(`${r.valid_from}Z`).getTime() < now,
  )

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Context registry</h1>
          <p className="mt-0.5 max-w-3xl text-xs leading-relaxed text-[--color-ink-muted]">
            Approved business justifications that damp risk inside their validity window. This is what
            keeps the triage queue readable — but damping is bounded, and evidence-destroying actions
            bypass it entirely, whatever the approval says.
          </p>
        </div>
        {can('analyst') && (
          <Button size="sm" variant="primary" onClick={() => setCreating(true)}>
            Register authorisation
          </Button>
        )}
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Panel className="px-4 py-3">
          <Stat label="Records" value={String(data?.meta.total ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Currently covering" value={String(covering.length)} accent="var(--color-suppressed)" />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Strongest damping"
            value={
              covering.length
                ? `×${Math.min(...covering.map((c) => c.damping_factor)).toFixed(2)}`
                : '—'
            }
            sublabel="Lowest multiplier in force"
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Applied"
            value={String(records.reduce((sum, r) => sum + r.applied_count, 0))}
            sublabel="Events damped"
          />
        </Panel>
      </div>

      <Panel className="p-3">
        <div className="grid gap-2 sm:grid-cols-3">
          <Select value={type} onChange={(e) => { setType(e.target.value); setPage(1) }}>
            <option value="">All types</option>
            {CONTEXT_TYPES.map((t) => (
              <option key={t} value={t}>
                {titleise(t)}
              </option>
            ))}
          </Select>
          <Button
            size="sm"
            variant={activeOnly ? 'primary' : 'subtle'}
            onClick={() => { setActiveOnly((v) => !v); setPage(1) }}
          >
            Active only
          </Button>
        </div>
      </Panel>

      <Panel>
        {isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : error ? (
          <ErrorState error={error} retry={() => void refetch()} />
        ) : !records.length ? (
          <EmptyState
            title="No context records"
            description="Without authorisations, every legitimate role change and approved migration will page an analyst."
          />
        ) : (
          <>
            <ul className="divide-y divide-[--color-border-subtle]">
              {records.map((record) => {
                const isCovering =
                  record.is_active &&
                  new Date(`${record.valid_until}Z`).getTime() > now &&
                  new Date(`${record.valid_from}Z`).getTime() < now
                return (
                  <li key={record.id} className="flex flex-wrap items-start gap-4 px-5 py-3.5">
                    <div className="min-w-64 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium">{record.title}</span>
                        <Badge className="py-0 text-[9px]">{titleise(record.context_type)}</Badge>
                        {record.ticket_reference && (
                          <Badge className="py-0 font-mono text-[9px]">{record.ticket_reference}</Badge>
                        )}
                        <Badge
                          className={cn(
                            'py-0 text-[9px]',
                            isCovering
                              ? 'border-indigo-500/30 bg-indigo-500/10 text-indigo-300'
                              : 'border-slate-500/30 bg-slate-500/10 text-slate-400',
                          )}
                        >
                          {isCovering ? 'covering now' : record.is_active ? 'scheduled / lapsed' : 'revoked'}
                        </Badge>
                      </div>

                      <p className="mt-1 text-xs leading-relaxed text-[--color-ink-muted]">
                        {record.description}
                      </p>

                      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[--color-ink-faint]">
                        <Link
                          to={`/investigate/${record.identity_id}`}
                          className="font-mono transition-colors hover:text-cyan-300"
                        >
                          {record.identity_id}
                        </Link>
                        <span>·</span>
                        <span>approved by {record.approved_by}</span>
                        <span>·</span>
                        <span>
                          {absoluteTime(record.valid_from, 'dd MMM')} → {absoluteTime(record.valid_until, 'dd MMM yyyy')}
                        </span>
                        <span>·</span>
                        <span>via {record.source_system}</span>
                      </div>

                      {record.target_resources.length > 0 && (
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {record.target_resources.map((resource) => (
                            <Badge key={resource} className="py-0 font-mono text-[9px]">
                              {resource}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="flex shrink-0 flex-col items-end gap-1.5">
                      <div className="text-right">
                        <p className="numeric text-sm font-semibold text-indigo-300">
                          ×{record.damping_factor.toFixed(2)}
                        </p>
                        <p className="text-[10px] text-[--color-ink-faint]">
                          {percent((1 - record.damping_factor) * 100)} reduction
                        </p>
                      </div>
                      {can('analyst') && record.is_active && (
                        <Button
                          size="sm"
                          variant="ghost"
                          loading={revoke.isPending}
                          onClick={() => revoke.mutate(record.id)}
                        >
                          Revoke
                        </Button>
                      )}
                    </div>
                  </li>
                )
              })}
            </ul>
            {data && <Pagination meta={data.meta} onPage={setPage} />}
          </>
        )}
      </Panel>

      <CreateContextModal open={creating} onClose={() => setCreating(false)} />
    </div>
  )
}

function CreateContextModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateContext()
  const { data: identities } = useIdentities({ page_size: 100 })

  const [identityId, setIdentityId] = useState('')
  const [contextType, setContextType] = useState('APPROVED_CHANGE_TICKET')
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [ticket, setTicket] = useState('')
  const [approvedBy, setApprovedBy] = useState('')
  const [damping, setDamping] = useState(0.35)
  const [days, setDays] = useState(14)
  const [resources, setResources] = useState('')
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setError(null)
    try {
      await create.mutateAsync({
        identity_id: identityId,
        context_type: contextType,
        title,
        description,
        ticket_reference: ticket || null,
        approved_by: approvedBy,
        damping_factor: damping,
        valid_days: days,
        target_resources: resources
          .split(',')
          .map((r) => r.trim())
          .filter(Boolean),
      })
      onClose()
      setTitle('')
      setDescription('')
      setTicket('')
      setResources('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the record.')
    }
  }

  const valid = identityId && title.length >= 3 && approvedBy.length >= 2

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Register an authorisation"
      description="Damps risk for the selected identity inside the validity window."
      width="max-w-2xl"
      footer={
        <>
          <Button size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" loading={create.isPending} disabled={!valid} onClick={() => void submit()}>
            Register
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Identity" className="sm:col-span-2">
          <Select value={identityId} onChange={(e) => setIdentityId(e.target.value)}>
            <option value="">Select an identity…</option>
            {(identities?.items ?? []).map((identity) => (
              <option key={identity.id} value={identity.id}>
                {identity.username} — {identity.role_title}, {identity.department}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Type">
          <Select value={contextType} onChange={(e) => setContextType(e.target.value)}>
            {CONTEXT_TYPES.map((t) => (
              <option key={t} value={t}>
                {titleise(t)}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Ticket reference" hint="Optional. Events tagged with it match exactly.">
          <Input value={ticket} onChange={(e) => setTicket(e.target.value)} placeholder="CHG-2026-0001" />
        </Field>

        <Field label="Title" className="sm:col-span-2">
          <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Data lake migration lead assignment" />
        </Field>

        <Field label="Description" className="sm:col-span-2">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Why this access is expected…" />
        </Field>

        <Field label="Approved by">
          <Input value={approvedBy} onChange={(e) => setApprovedBy(e.target.value)} placeholder="Name and role" />
        </Field>

        <Field label="Valid for (days)">
          <Input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
        </Field>

        <Field
          label={`Damping factor — ×${damping.toFixed(2)} (${percent((1 - damping) * 100)} reduction)`}
          hint="Bounded to 0.10–0.95. Nothing is ever fully silenced."
          className="sm:col-span-2"
        >
          <input
            type="range"
            min={0.1}
            max={0.95}
            step={0.05}
            value={damping}
            onChange={(e) => setDamping(Number(e.target.value))}
            className="w-full accent-cyan-400"
          />
        </Field>

        <Field
          label="Target resources"
          hint="Comma-separated. Leaving this empty creates a blanket approval, which damps less aggressively."
          className="sm:col-span-2"
        >
          <Input
            value={resources}
            onChange={(e) => setResources(e.target.value)}
            placeholder="prod_datalake_s3, snowflake_titan_lake"
          />
        </Field>

        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/8 px-3 py-2 text-xs text-rose-200 sm:col-span-2">
            {error}
          </div>
        )}
      </div>
    </Modal>
  )
}

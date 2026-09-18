import { useState } from 'react'
import type { Investigation } from '@/types/api'
import { useAuth } from '@/lib/auth'
import { useExecuteAction, usePlaybooks, useRunPlaybook } from '@/lib/queries'
import { Badge, Button, EmptyState, Field, Input, Modal, Panel } from '@/components/ui'
import { IconLock, IconPlay, IconShield } from '@/components/ui/icons'
import { relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'

const ACTIONS: { id: string; label: string; description: string; destructive?: boolean }[] = [
  { id: 'STEP_UP_MFA', label: 'Step-up MFA', description: 'Push an MFA challenge to verify the human behind the session.' },
  { id: 'NOTIFY_MANAGER', label: 'Notify manager', description: 'Ask the reporting manager to confirm the activity out of band.' },
  { id: 'OPEN_TICKET', label: 'Open ticket', description: 'Raise a tracked investigation ticket in the ITSM system.' },
  { id: 'REVOKE_TOKENS', label: 'Revoke tokens', description: 'Invalidate refresh tokens and OAuth grants.', destructive: true },
  { id: 'SUSPEND_API_KEYS', label: 'Suspend API keys', description: 'Disable machine credentials issued to this identity.', destructive: true },
  { id: 'QUARANTINE_SESSION', label: 'Quarantine sessions', description: 'Terminate active sessions and isolate the endpoint.', destructive: true },
  { id: 'DISABLE_ACCOUNT', label: 'Disable account', description: 'Suspend the account pending identity verification.', destructive: true },
  { id: 'ESCALATE', label: 'Escalate to Tier-3', description: 'Hand off to incident response with the forensic dossier.' },
  { id: 'RE_BASELINE', label: 'Re-baseline', description: 'Fold current behaviour into the learned norm.' },
  { id: 'ADD_CONTEXT_EXEMPTION', label: 'Record exemption', description: 'Attach an approved business justification. Requires a note.' },
]

export function ResponseTab({ data }: { data: Investigation }) {
  const { can } = useAuth()
  const execute = useExecuteAction()
  const runPlaybook = useRunPlaybook()
  const { data: playbooks } = usePlaybooks()

  const [pending, setPending] = useState<(typeof ACTIONS)[number] | null>(null)
  const [notes, setNotes] = useState('')
  const [feedback, setFeedback] = useState<string | null>(null)
  const [plan, setPlan] = useState<{ slug: string; steps: { step: number; label: string; outcome: string }[] } | null>(null)

  const authorised = can('responder')

  const confirm = async () => {
    if (!pending) return
    try {
      await execute.mutateAsync({ identityId: data.identity.id, action: pending.id, notes: notes || undefined })
      setFeedback(`${pending.label} executed and written to the audit log.`)
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : 'Action failed.')
    } finally {
      setPending(null)
      setNotes('')
    }
  }

  return (
    <div className="space-y-5">
      {!authorised && (
        <div className="flex items-center gap-2.5 rounded-lg border border-amber-500/25 bg-amber-500/5 px-4 py-2.5">
          <IconLock className="size-4 shrink-0 text-amber-400" />
          <p className="text-xs text-amber-200/80">
            Containment actions require the <strong>responder</strong> role. You can review the plan
            but not execute it.
          </p>
        </div>
      )}

      {feedback && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-4 py-2.5">
          <p className="text-xs text-emerald-200">{feedback}</p>
          <Button size="sm" variant="ghost" onClick={() => setFeedback(null)}>
            Dismiss
          </Button>
        </div>
      )}

      <section>
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Individual actions
        </h3>
        <p className="mb-3 text-xs text-[--color-ink-muted]">
          Each execution re-scores the identity and is written to the immutable audit log.
        </p>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {ACTIONS.map((action) => (
            <button
              key={action.id}
              disabled={!authorised}
              onClick={() => setPending(action)}
              className={cn(
                'rounded-lg border px-3.5 py-3 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-45',
                action.destructive
                  ? 'border-rose-500/25 bg-rose-500/5 hover:border-rose-500/45'
                  : 'border-[--color-border-subtle] bg-[--color-surface-raised] hover:border-[--color-border-strong]',
              )}
            >
              <div className="flex items-center gap-2">
                <p className={cn('text-xs font-medium', action.destructive && 'text-rose-200')}>
                  {action.label}
                </p>
                {action.destructive && (
                  <Badge className="border-rose-500/30 bg-rose-500/10 py-0 text-[9px] text-rose-300">
                    enforcing
                  </Badge>
                )}
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-[--color-ink-muted]">
                {action.description}
              </p>
            </button>
          ))}
        </div>
      </section>

      <section>
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Playbooks
        </h3>
        <p className="mb-3 text-xs text-[--color-ink-muted]">
          Ordered sequences of actions. Previewing a playbook plans it without enforcing anything.
        </p>
        <div className="grid gap-3 lg:grid-cols-2">
          {(playbooks ?? []).map((playbook) => (
            <Panel key={playbook.id} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-medium">{playbook.name}</p>
                  <p className="mt-0.5 text-xs leading-relaxed text-[--color-ink-muted]">
                    {playbook.description}
                  </p>
                </div>
                <Badge className="shrink-0">{playbook.steps.length} steps</Badge>
              </div>

              <ol className="mt-3 space-y-1">
                {playbook.steps.map((step, i) => (
                  <li key={i} className="flex gap-2 text-[11px] text-[--color-ink-muted]">
                    <span className="numeric text-[--color-ink-faint]">{i + 1}.</span>
                    <span>{step.label}</span>
                  </li>
                ))}
              </ol>

              <div className="mt-3 flex items-center gap-2 border-t border-[--color-border-subtle] pt-3">
                <Button
                  size="sm"
                  icon={<IconPlay className="size-3" />}
                  loading={runPlaybook.isPending}
                  onClick={async () => {
                    const result = await runPlaybook.mutateAsync({
                      slug: playbook.slug,
                      identityId: data.identity.id,
                      dryRun: true,
                    })
                    setPlan({ slug: playbook.slug, steps: result.steps })
                  }}
                >
                  Preview plan
                </Button>
                <span className="text-[10px] text-[--color-ink-faint]">
                  ~{playbook.estimated_minutes} min
                  {playbook.requires_approval && ' · approval required'}
                </span>
              </div>
            </Panel>
          ))}
        </div>
      </section>

      <section>
        <h3 className="mb-3 text-xs font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Response history
        </h3>
        {data.actions.length === 0 ? (
          <EmptyState
            icon={<IconShield className="size-7" />}
            title="No actions taken"
            description="Nothing has been executed against this identity."
          />
        ) : (
          <ul className="divide-y divide-[--color-border-subtle] rounded-lg border border-[--color-border-subtle]">
            {data.actions.map((action) => (
              <li key={action.id} className="flex items-center gap-3 px-4 py-2.5">
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-medium">{titleise(action.action)}</p>
                  <p className="truncate text-[11px] text-[--color-ink-faint]">
                    {action.is_automated ? 'automation' : action.performed_by}
                    {action.notes && ` — ${action.notes}`}
                  </p>
                </div>
                <Badge
                  className={cn(
                    'shrink-0 py-0 text-[9px]',
                    action.outcome === 'SUCCEEDED' && 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
                  )}
                >
                  {action.outcome}
                </Badge>
                <span className="shrink-0 text-[10px] text-[--color-ink-faint]">
                  {relativeTime(action.created_at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* ------------------------------------------------------- dialogues */}
      <Modal
        open={Boolean(pending)}
        onClose={() => setPending(null)}
        title={`Execute: ${pending?.label ?? ''}`}
        description={pending?.description}
        footer={
          <>
            <Button size="sm" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button
              size="sm"
              variant={pending?.destructive ? 'danger' : 'primary'}
              loading={execute.isPending}
              onClick={() => void confirm()}
              disabled={pending?.id === 'ADD_CONTEXT_EXEMPTION' && !notes.trim()}
            >
              Confirm
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-xs text-[--color-ink-muted]">
            Target: <span className="font-mono text-[--color-ink]">{data.identity.username}</span> (
            {data.identity.role_title}, {data.identity.department})
          </p>
          {pending?.destructive && (
            <div className="rounded-lg border border-rose-500/25 bg-rose-500/5 px-3 py-2.5 text-xs text-rose-200/85">
              This is an enforcing action. It changes the identity's access posture and closes their
              open alerts as confirmed incidents.
            </div>
          )}
          <Field
            label="Notes"
            hint={
              pending?.id === 'ADD_CONTEXT_EXEMPTION'
                ? 'Required — this becomes the recorded justification.'
                : 'Optional. Recorded alongside the action in the audit log.'
            }
          >
            <Input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Reason for this action…" />
          </Field>
        </div>
      </Modal>

      <Modal
        open={Boolean(plan)}
        onClose={() => setPlan(null)}
        title="Playbook plan"
        description="Dry run — nothing has been executed."
        footer={
          <Button size="sm" onClick={() => setPlan(null)}>
            Close
          </Button>
        }
      >
        <ol className="space-y-2">
          {plan?.steps.map((step) => (
            <li
              key={step.step}
              className="flex items-center gap-3 rounded-lg border border-[--color-border-subtle] px-3 py-2"
            >
              <span className="numeric text-xs text-[--color-ink-faint]">{step.step}</span>
              <span className="flex-1 text-xs">{step.label}</span>
              <Badge className="py-0 text-[9px]">{step.outcome}</Badge>
            </li>
          ))}
        </ol>
      </Modal>
    </div>
  )
}

import { useState } from 'react'
import { useIdentities, usePlaybooks, useRunPlaybook } from '@/lib/queries'
import { useAuth } from '@/lib/auth'
import { Badge, Button, EmptyState, Modal, Panel, PanelHeader, Select, Skeleton, Stat } from '@/components/ui'
import { IconPlay, IconShield } from '@/components/ui/icons'
import { relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'

export function ResponsePage() {
  const { can } = useAuth()
  const { data: playbooks, isLoading } = usePlaybooks()
  const { data: identities } = useIdentities({ page_size: 100, sort_by: 'risk_score', sort_dir: 'desc' })
  const runPlaybook = useRunPlaybook()

  const [selected, setSelected] = useState<string | null>(null)
  const [target, setTarget] = useState('')
  const [plan, setPlan] = useState<{ steps: { step: number; label: string; outcome: string }[] } | null>(null)

  const playbook = playbooks?.find((p) => p.slug === selected)

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Response playbooks</h1>
        <p className="mt-0.5 max-w-3xl text-xs leading-relaxed text-[--color-ink-muted]">
          Ordered sequences of containment actions. Previewing a playbook plans it without enforcing
          anything, so an analyst can see exactly what would happen before it happens.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Panel className="px-4 py-3">
          <Stat label="Playbooks" value={String(playbooks?.length ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Enabled" value={String(playbooks?.filter((p) => p.enabled).length ?? 0)} accent="var(--color-stable)" />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Total runs" value={String(playbooks?.reduce((s, p) => s + p.run_count, 0) ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Require approval"
            value={String(playbooks?.filter((p) => p.requires_approval).length ?? 0)}
            sublabel="Never auto-execute"
          />
        </Panel>
      </div>

      {isLoading ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-56" />
          ))}
        </div>
      ) : !playbooks?.length ? (
        <EmptyState title="No playbooks configured" icon={<IconShield className="size-8" />} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {playbooks.map((p) => (
            <Panel key={p.id} lit className="flex flex-col">
              <PanelHeader
                icon={<IconShield className="size-4" />}
                title={p.name}
                subtitle={p.description}
                action={
                  <div className="flex shrink-0 gap-1.5">
                    <Badge className="py-0 text-[9px]">{titleise(p.category)}</Badge>
                    {p.requires_approval && (
                      <Badge className="border-amber-500/30 bg-amber-500/10 py-0 text-[9px] text-amber-300">
                        approval
                      </Badge>
                    )}
                  </div>
                }
              />

              <ol className="flex-1 space-y-2 px-5 py-4">
                {p.steps.map((step, i) => (
                  <li key={i} className="flex gap-3">
                    <span className="numeric mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border border-[--color-border] text-[10px] text-[--color-ink-faint]">
                      {i + 1}
                    </span>
                    <div>
                      <p className="text-xs font-medium">{step.label}</p>
                      <p className="text-[11px] leading-relaxed text-[--color-ink-muted]">
                        {step.description}
                      </p>
                    </div>
                  </li>
                ))}
              </ol>

              <div className="flex flex-wrap items-center gap-3 border-t border-[--color-border-subtle] px-5 py-3 text-[10px] text-[--color-ink-faint]">
                <span>~{p.estimated_minutes} min</span>
                <span>·</span>
                <span>{p.run_count} run(s)</span>
                {p.last_run_at && (
                  <>
                    <span>·</span>
                    <span>last {relativeTime(p.last_run_at)}</span>
                  </>
                )}
                {can('responder') && (
                  <Button
                    size="sm"
                    className="ml-auto"
                    icon={<IconPlay className="size-3" />}
                    onClick={() => {
                      setSelected(p.slug)
                      setTarget('')
                      setPlan(null)
                    }}
                  >
                    Preview
                  </Button>
                )}
              </div>
            </Panel>
          ))}
        </div>
      )}

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={playbook?.name ?? ''}
        description="Select a target identity to plan this playbook. Nothing is executed."
        footer={
          <>
            <Button size="sm" onClick={() => setSelected(null)}>
              Close
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={!target}
              loading={runPlaybook.isPending}
              onClick={async () => {
                if (!selected || !target) return
                const result = await runPlaybook.mutateAsync({
                  slug: selected,
                  identityId: target,
                  dryRun: true,
                })
                setPlan({ steps: result.steps })
              }}
            >
              Plan
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Select value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">Select a target identity…</option>
            {(identities?.items ?? []).map((i) => (
              <option key={i.id} value={i.id}>
                {i.username} — risk {i.risk_score.toFixed(0)} ({titleise(i.transition_state)})
              </option>
            ))}
          </Select>

          {plan && (
            <ol className="space-y-2">
              {plan.steps.map((step) => (
                <li
                  key={step.step}
                  className={cn(
                    'flex items-center gap-3 rounded-lg border px-3 py-2',
                    'border-[--color-border-subtle] bg-[--color-surface-raised]',
                  )}
                >
                  <span className="numeric text-xs text-[--color-ink-faint]">{step.step}</span>
                  <span className="flex-1 text-xs">{step.label}</span>
                  <Badge className="py-0 text-[9px]">{step.outcome}</Badge>
                </li>
              ))}
            </ol>
          )}

          <p className="text-[11px] leading-relaxed text-[--color-ink-faint]">
            To execute a playbook for real, open the target identity's workbench and use the Response
            tab — enforcement is deliberately one step away from a list view.
          </p>
        </div>
      </Modal>
    </div>
  )
}

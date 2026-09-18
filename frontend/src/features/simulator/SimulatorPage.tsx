import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  useEstate,
  useIdentities,
  useInjectEvent,
  useResetEstate,
  useRunScenario,
  useScenarios,
} from '@/lib/queries'
import { useAuth } from '@/lib/auth'
import {
  Badge,
  Button,
  Field,
  Input,
  Modal,
  Panel,
  PanelHeader,
  Select,
  Skeleton,
  Stat,
} from '@/components/ui'
import { IconFlask, IconPlay, IconRefresh } from '@/components/ui/icons'
import { StateBadge } from '@/features/dashboard/CommandCenter'
import { compactNumber, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { ScenarioResult } from '@/types/api'

export function SimulatorPage() {
  const { can } = useAuth()
  const { data: scenarios, isLoading } = useScenarios()
  const { data: estate } = useEstate()
  const run = useRunScenario()
  const reset = useResetEstate()

  const [results, setResults] = useState<Record<string, ScenarioResult>>({})
  const [running, setRunning] = useState<string | null>(null)
  const [confirmReset, setConfirmReset] = useState(false)

  const execute = async (id: string) => {
    setRunning(id)
    try {
      const result = await run.mutateAsync(id)
      setResults((prev) => ({ ...prev, [id]: result }))
    } finally {
      setRunning(null)
    }
  }

  const runAll = async () => {
    for (const scenario of scenarios ?? []) {
      await execute(scenario.id)
    }
  }

  const ran = Object.values(results)
  const passed = ran.filter((r) => r.outcome_matches_expectation).length

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Threat simulator</h1>
          <p className="mt-0.5 max-w-3xl text-xs leading-relaxed text-[--color-ink-muted]">
            Each scenario injects real telemetry through the live ingestion pipeline and declares the
            outcome it expects. Running one reports whether the engine actually produced that outcome —
            so this is a regression harness, not a scripted demo.
          </p>
        </div>
        <div className="flex gap-2">
          {can('analyst') && (
            <Button
              size="sm"
              variant="primary"
              icon={<IconPlay className="size-3" />}
              loading={Boolean(running)}
              onClick={() => void runAll()}
            >
              Run all scenarios
            </Button>
          )}
          {can('admin') && (
            <Button size="sm" variant="danger" onClick={() => setConfirmReset(true)}>
              Reset estate
            </Button>
          )}
        </div>
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Panel className="px-4 py-3">
          <Stat label="Identities" value={String(estate?.identities ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Events" value={compactNumber(estate?.events ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Alerts" value={String(estate?.alerts ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Contexts" value={String(estate?.contexts ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Harness"
            value={ran.length ? `${passed}/${ran.length}` : '—'}
            sublabel={ran.length ? 'expectations met' : 'not run yet'}
            accent={
              ran.length === 0
                ? undefined
                : passed === ran.length
                  ? 'var(--color-stable)'
                  : 'var(--color-critical)'
            }
          />
        </Panel>
      </div>

      {isLoading ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-64" />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {(scenarios ?? []).map((scenario) => {
            const result = results[scenario.id]
            const isRunning = running === scenario.id
            return (
              <Panel key={scenario.id} lit className="flex flex-col">
                <PanelHeader
                  icon={<IconFlask className="size-4" />}
                  title={scenario.title}
                  subtitle={scenario.subtitle}
                  action={<Badge className="py-0 text-[9px]">{scenario.event_count} events</Badge>}
                />

                <div className="flex-1 px-5 py-4">
                  <p className="text-xs leading-relaxed text-[--color-ink-muted]">{scenario.narrative}</p>

                  <dl className="mt-3 space-y-1.5 border-t border-[--color-border-subtle] pt-3 text-[11px]">
                    <Row label="Target" value={<span className="font-mono">{scenario.target_username}</span>} />
                    <Row
                      label="Expected"
                      value={
                        <span className="flex items-center gap-1.5">
                          <StateBadge state={scenario.expected_state} />
                          <span className="text-[--color-ink-faint]">
                            {scenario.expect_exact ? '(exactly)' : '(or worse)'}
                          </span>
                        </span>
                      }
                    />
                    <Row label="Window" value={`${scenario.duration_days} day(s)`} />
                  </dl>

                  <p className="mt-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-[11px] leading-relaxed text-cyan-100/80">
                    <span className="font-medium">What this proves: </span>
                    {scenario.teaches}
                  </p>

                  {result && (
                    <div
                      className={cn(
                        'mt-3 rounded-lg border px-3 py-2.5',
                        result.outcome_matches_expectation
                          ? 'border-emerald-500/30 bg-emerald-500/8'
                          : 'border-rose-500/30 bg-rose-500/8',
                      )}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={cn(
                            'text-xs font-semibold',
                            result.outcome_matches_expectation ? 'text-emerald-300' : 'text-rose-300',
                          )}
                        >
                          {result.outcome_matches_expectation ? 'Expectation met' : 'Expectation missed'}
                        </span>
                        <span className="numeric text-xs text-[--color-ink-muted]">
                          {result.risk_before.toFixed(1)} → {result.risk_after.toFixed(1)}
                        </span>
                        <StateBadge state={result.state_after} />
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {result.damping_applied && (
                          <Badge className="border-indigo-500/30 bg-indigo-500/10 py-0 text-[9px] text-indigo-300">
                            context damped
                          </Badge>
                        )}
                        {result.anti_tamper_triggered && (
                          <Badge className="border-rose-500/40 bg-rose-500/10 py-0 text-[9px] text-rose-300">
                            anti-tamper fired
                          </Badge>
                        )}
                        <Badge className="py-0 text-[9px]">
                          {result.matched_rules.length} rule(s) matched
                        </Badge>
                        <Badge className="py-0 text-[9px]">{result.events_injected} events injected</Badge>
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 border-t border-[--color-border-subtle] px-5 py-3">
                  {can('analyst') && (
                    <Button
                      size="sm"
                      variant="primary"
                      loading={isRunning}
                      icon={<IconPlay className="size-3" />}
                      onClick={() => void execute(scenario.id)}
                    >
                      Run scenario
                    </Button>
                  )}
                  {result && (
                    <Link to={`/investigate/${result.identity_id}`}>
                      <Button size="sm">Investigate result →</Button>
                    </Link>
                  )}
                </div>
              </Panel>
            )
          })}
        </div>
      )}

      <InjectorPanel />

      <Modal
        open={confirmReset}
        onClose={() => setConfirmReset(false)}
        title="Reset the estate"
        description="Destructive and irreversible."
        footer={
          <>
            <Button size="sm" onClick={() => setConfirmReset(false)}>
              Cancel
            </Button>
            <Button
              size="sm"
              variant="danger"
              loading={reset.isPending}
              onClick={async () => {
                await reset.mutateAsync()
                setResults({})
                setConfirmReset(false)
              }}
            >
              Reset everything
            </Button>
          </>
        }
      >
        <p className="text-xs leading-relaxed text-[--color-ink-muted]">
          This deletes all telemetry, alerts, cases, context records and response history, then
          regenerates the seeded estate and re-learns every baseline from scratch. It takes around a
          minute and cannot be undone.
        </p>
      </Modal>
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-[--color-ink-faint]">{label}</dt>
      <dd className="text-[--color-ink]">{value}</dd>
    </div>
  )
}

/** Manual single-event injector — the fastest way to feel how scoring responds. */
function InjectorPanel() {
  const { can } = useAuth()
  const { data: identities } = useIdentities({ page_size: 100 })
  const inject = useInjectEvent()

  const [identity, setIdentity] = useState('')
  const [eventType, setEventType] = useState('API_CALL')
  const [resource, setResource] = useState('prod_customer_sql_replica')
  const [action, setAction] = useState('query_bulk')
  const [sensitivity, setSensitivity] = useState(4)
  const [offHours, setOffHours] = useState(true)
  const [records, setRecords] = useState(50000)
  const [feedback, setFeedback] = useState<string | null>(null)

  if (!can('analyst')) return null

  const submit = async () => {
    setFeedback(null)
    try {
      await inject.mutateAsync({
        identity,
        event_type: eventType,
        resource,
        action,
        sensitivity_level: sensitivity,
        is_off_hours: offHours,
        record_count: records,
        source: 'console',
      })
      setFeedback('Event ingested and the identity re-scored. Open their workbench to see the effect.')
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : 'Injection failed.')
    }
  }

  return (
    <Panel>
      <PanelHeader
        icon={<IconRefresh className="size-4" />}
        title="Manual event injector"
        subtitle="Push a single synthetic event through the real ingestion and scoring path."
      />
      <div className="grid gap-3 px-5 py-4 sm:grid-cols-2 lg:grid-cols-4">
        <Field label="Identity">
          <Select value={identity} onChange={(e) => setIdentity(e.target.value)}>
            <option value="">Select…</option>
            {(identities?.items ?? []).map((i) => (
              <option key={i.id} value={i.id}>
                {i.username}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Event type">
          <Select value={eventType} onChange={(e) => setEventType(e.target.value)}>
            {[
              'API_CALL', 'FILE_ACCESS', 'AUTHENTICATION', 'PRIVILEGE_ACTION',
              'NETWORK_EGRESS', 'ROLE_MODIFICATION', 'DATA_EXPORT', 'SECRET_ACCESS',
            ].map((t) => (
              <option key={t} value={t}>
                {titleise(t)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Resource">
          <Input value={resource} onChange={(e) => setResource(e.target.value)} />
        </Field>
        <Field label="Action">
          <Input value={action} onChange={(e) => setAction(e.target.value)} />
        </Field>
        <Field label={`Sensitivity — Tier ${sensitivity}`}>
          <input
            type="range"
            min={1}
            max={5}
            value={sensitivity}
            onChange={(e) => setSensitivity(Number(e.target.value))}
            className="w-full accent-cyan-400"
          />
        </Field>
        <Field label="Record count">
          <Input type="number" min={0} value={records} onChange={(e) => setRecords(Number(e.target.value))} />
        </Field>
        <Field label="Timing">
          <Button
            size="md"
            variant={offHours ? 'primary' : 'subtle'}
            onClick={() => setOffHours((v) => !v)}
            className="w-full"
          >
            {offHours ? 'Off hours' : 'Business hours'}
          </Button>
        </Field>
        <div className="flex items-end">
          <Button
            variant="primary"
            className="w-full"
            loading={inject.isPending}
            disabled={!identity}
            onClick={() => void submit()}
          >
            Inject event
          </Button>
        </div>
      </div>
      {feedback && (
        <p className="border-t border-[--color-border-subtle] px-5 py-2.5 text-xs text-[--color-ink-muted]">
          {feedback}
        </p>
      )}
    </Panel>
  )
}

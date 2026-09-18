import { useState } from 'react'
import { useRuleStats, useRules, useTestRule, useToggleRule } from '@/lib/queries'
import { useAuth } from '@/lib/auth'
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Field,
  Modal,
  Panel,
  PanelHeader,
  Select,
  Skeleton,
  Stat,
} from '@/components/ui'
import { Pagination } from '@/components/ui/pagination'
import { SeverityBadge } from '@/features/dashboard/CommandCenter'
import { relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { DetectionRule } from '@/types/api'

interface RuleStat {
  id: string
  slug: string
  name: string
  precision: number | null
  match_count: number
  false_positives: number
}

const SAMPLE_CONDITION = `{
  "all": [
    { "field": "sensitivity_level", "op": "gte", "value": 4 },
    { "field": "action", "op": "in", "value": ["export", "export_all"] },
    {
      "any": [
        { "field": "is_off_hours", "op": "is_true" },
        { "field": "vectors.geovelocity", "op": "gte", "value": 70 }
      ]
    }
  ]
}`

export function DetectionsPage() {
  const { can } = useAuth()
  const [category, setCategory] = useState('')
  const [severity, setSeverity] = useState('')
  const [page, setPage] = useState(1)
  const [inspecting, setInspecting] = useState<DetectionRule | null>(null)
  const [testerOpen, setTesterOpen] = useState(false)

  const { data, isLoading, error, refetch } = useRules({
    page,
    page_size: 20,
    category: category || undefined,
    severity: severity || undefined,
  })
  const { data: stats } = useRuleStats()
  const toggle = useToggleRule()

  const s = stats as
    | { total: number; enabled: number; builtin: number; total_matches: number; tuning_candidates: RuleStat[] }
    | undefined

  const categories = [...new Set((data?.items ?? []).map((r) => r.category))]

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Detections</h1>
          <p className="mt-0.5 text-xs text-[--color-ink-muted]">
            Declarative rules layered on top of the statistical engine. Authored as JSON, evaluated
            against every scored event.
          </p>
        </div>
        <Button size="sm" variant="primary" onClick={() => setTesterOpen(true)}>
          Rule tester
        </Button>
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Panel className="px-4 py-3">
          <Stat label="Rules" value={String(s?.total ?? 0)} sublabel={`${s?.builtin ?? 0} built-in`} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Enabled" value={String(s?.enabled ?? 0)} accent="var(--color-stable)" />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Total matches" value={String(s?.total_matches ?? 0)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Tuning candidates"
            value={String(s?.tuning_candidates?.length ?? 0)}
            sublabel="Precision below 50%"
            accent={(s?.tuning_candidates?.length ?? 0) > 0 ? 'var(--color-drift)' : undefined}
          />
        </Panel>
      </div>

      {s?.tuning_candidates && s.tuning_candidates.length > 0 && (
        <Panel className="border-amber-500/25 bg-amber-500/5">
          <PanelHeader
            title="Rules worth tuning"
            subtitle="These are producing more false positives than true ones. Precision comes from analyst dispositions on the triage queue."
          />
          <ul className="divide-y divide-amber-500/10">
            {s.tuning_candidates.map((rule) => (
              <li key={rule.id} className="flex items-center gap-3 px-5 py-2.5">
                <span className="flex-1 truncate text-xs">{rule.name}</span>
                <span className="numeric text-xs text-amber-300">{rule.precision}% precision</span>
                <span className="text-[10px] text-[--color-ink-faint]">
                  {rule.false_positives} FP / {rule.match_count} matches
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel className="p-3">
        <div className="grid gap-2 sm:grid-cols-3">
          <Select value={category} onChange={(e) => { setCategory(e.target.value); setPage(1) }}>
            <option value="">All categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {titleise(c)}
              </option>
            ))}
          </Select>
          <Select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}>
            <option value="">All severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((v) => (
              <option key={v} value={v}>
                {titleise(v)}
              </option>
            ))}
          </Select>
        </div>
      </Panel>

      <Panel>
        {isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-16" />
            ))}
          </div>
        ) : error ? (
          <ErrorState error={error} retry={() => void refetch()} />
        ) : !data?.items.length ? (
          <EmptyState title="No rules match" description="Adjust the filters above." />
        ) : (
          <>
            <ul className="divide-y divide-[--color-border-subtle]">
              {data.items.map((rule) => {
                const judged = rule.true_positive_count + rule.false_positive_count
                const precision = judged ? Math.round((rule.true_positive_count / judged) * 100) : null
                return (
                  <li key={rule.id} className="flex flex-wrap items-start gap-4 px-5 py-3.5">
                    <div className="min-w-64 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          onClick={() => setInspecting(rule)}
                          className="text-sm font-medium transition-colors hover:text-cyan-200"
                        >
                          {rule.name}
                        </button>
                        <SeverityBadge severity={rule.severity} />
                        <Badge className="py-0 text-[9px]">{titleise(rule.category)}</Badge>
                        {rule.is_builtin && <Badge className="py-0 text-[9px]">built-in</Badge>}
                        {!rule.suppress_when_context && (
                          <Badge
                            className="border-rose-500/30 bg-rose-500/10 py-0 text-[9px] text-rose-300"
                            title="This rule fires even when an approved business context is active."
                          >
                            never suppressed
                          </Badge>
                        )}
                      </div>
                      <p className="mt-1 text-xs leading-relaxed text-[--color-ink-muted]">
                        {rule.description}
                      </p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[--color-ink-faint]">
                        <span className="font-mono">{rule.slug}</span>
                        <span>·</span>
                        <span>+{rule.risk_boost} boost</span>
                        <span>·</span>
                        <span>{rule.match_count} matches</span>
                        {precision !== null && (
                          <>
                            <span>·</span>
                            <span className={cn(precision < 50 ? 'text-amber-400' : 'text-emerald-400')}>
                              {precision}% precision
                            </span>
                          </>
                        )}
                        {rule.last_matched_at && (
                          <>
                            <span>·</span>
                            <span>last {relativeTime(rule.last_matched_at)}</span>
                          </>
                        )}
                      </div>
                      {rule.mitre_techniques.length > 0 && (
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {rule.mitre_techniques.map((t) => (
                            <Badge key={t} className="py-0 font-mono text-[9px]">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="flex shrink-0 items-center gap-2">
                      <Button size="sm" variant="ghost" onClick={() => setInspecting(rule)}>
                        Logic
                      </Button>
                      {can('analyst') && (
                        <Button
                          size="sm"
                          variant={rule.enabled ? 'subtle' : 'primary'}
                          loading={toggle.isPending}
                          onClick={() => toggle.mutate({ id: rule.id, enabled: !rule.enabled })}
                        >
                          {rule.enabled ? 'Disable' : 'Enable'}
                        </Button>
                      )}
                    </div>
                  </li>
                )
              })}
            </ul>
            <Pagination meta={data.meta} onPage={setPage} />
          </>
        )}
      </Panel>

      <Modal
        open={Boolean(inspecting)}
        onClose={() => setInspecting(null)}
        title={inspecting?.name ?? ''}
        description={inspecting?.description}
        width="max-w-2xl"
        footer={
          <Button size="sm" onClick={() => setInspecting(null)}>
            Close
          </Button>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Risk boost" value={`+${inspecting?.risk_boost}`} />
            <Stat label="Matches" value={String(inspecting?.match_count ?? 0)} />
            <Stat label="True positives" value={String(inspecting?.true_positive_count ?? 0)} />
            <Stat label="False positives" value={String(inspecting?.false_positive_count ?? 0)} />
          </div>
          <div>
            <p className="mb-1.5 text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
              Condition tree
            </p>
            <pre className="overflow-x-auto rounded-lg border border-[--color-border-subtle] bg-[--color-void] p-3 font-mono text-[11px] leading-relaxed text-[--color-ink-muted]">
              {JSON.stringify(inspecting?.conditions ?? {}, null, 2)}
            </pre>
          </div>
          {(inspecting?.recommended_actions.length ?? 0) > 0 && (
            <div>
              <p className="mb-1.5 text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                Recommended response
              </p>
              <div className="flex flex-wrap gap-1.5">
                {inspecting?.recommended_actions.map((a) => (
                  <Badge key={a}>{titleise(a)}</Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </Modal>

      <RuleTester open={testerOpen} onClose={() => setTesterOpen(false)} />
    </div>
  )
}

function RuleTester({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [source, setSource] = useState(SAMPLE_CONDITION)
  const [parseError, setParseError] = useState<string | null>(null)
  const test = useTestRule()

  const run = async () => {
    setParseError(null)
    let conditions: Record<string, unknown>
    try {
      conditions = JSON.parse(source)
    } catch (err) {
      setParseError(err instanceof Error ? err.message : 'Invalid JSON')
      return
    }
    await test.mutateAsync(conditions)
  }

  const result = test.data

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Rule tester"
      description="Validate a condition tree and evaluate it against a representative high-risk event before committing it."
      width="max-w-3xl"
      footer={
        <>
          <Button size="sm" onClick={onClose}>
            Close
          </Button>
          <Button size="sm" variant="primary" loading={test.isPending} onClick={() => void run()}>
            Evaluate
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Conditions (JSON)" hint="Combinators: all, any, not. Operators: eq, ne, gt, gte, lt, lte, in, not_in, contains, startswith, endswith, matches, between, is_true, is_false.">
          <textarea
            value={source}
            onChange={(e) => setSource(e.target.value)}
            spellCheck={false}
            rows={14}
            className="w-full rounded-lg border border-[--color-border] bg-[--color-void] p-3 font-mono text-[11px] leading-relaxed text-[--color-ink] focus:border-cyan-400/50 focus:outline-none"
          />
        </Field>

        {parseError && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/8 px-3 py-2 text-xs text-rose-200">
            JSON parse error: {parseError}
          </div>
        )}

        {result && (
          <div
            className={cn(
              'rounded-lg border px-3 py-2.5',
              !result.valid
                ? 'border-rose-500/30 bg-rose-500/8'
                : result.matched
                  ? 'border-emerald-500/30 bg-emerald-500/8'
                  : 'border-[--color-border] bg-[--color-surface-raised]',
            )}
          >
            {!result.valid ? (
              <p className="text-xs text-rose-200">Invalid: {result.error}</p>
            ) : (
              <p className="text-xs">
                <span className={result.matched ? 'text-emerald-300' : 'text-[--color-ink-muted]'}>
                  {result.matched
                    ? 'Matched — this rule would fire on the sample event.'
                    : 'Valid, but did not match the sample event.'}
                </span>
              </p>
            )}
          </div>
        )}

        {result?.facts && (
          <details className="rounded-lg border border-[--color-border-subtle]">
            <summary className="cursor-pointer px-3 py-2 text-xs text-[--color-ink-muted]">
              Sample event facts
            </summary>
            <pre className="max-h-48 overflow-auto border-t border-[--color-border-subtle] p-3 font-mono text-[10px] text-[--color-ink-muted]">
              {JSON.stringify(result.facts, null, 2)}
            </pre>
          </details>
        )}
      </div>
    </Modal>
  )
}

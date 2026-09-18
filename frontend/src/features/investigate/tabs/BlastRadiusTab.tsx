import type { Investigation } from '@/types/api'
import { Badge, Panel, Stat } from '@/components/ui'
import { BlastGraph } from '@/components/charts/BlastGraph'
import { compactNumber, fullNumber, SENSITIVITY_LABELS } from '@/lib/format'
import { cn } from '@/lib/utils'

export function BlastRadiusTab({ data }: { data: Investigation }) {
  const blast = data.blast_radius

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Panel className="px-4 py-3">
          <Stat
            label="Blast radius"
            value={blast.blast_radius_score.toFixed(0)}
            sublabel={blast.impact_level}
            accent={blast.blast_radius_score >= 60 ? 'var(--color-critical)' : 'var(--color-drift)'}
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Assets reached" value={String(blast.assets_touched)} sublabel={`${blast.crown_jewels_touched} crown jewels`} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat label="Records at risk" value={compactNumber(blast.records_at_risk)} sublabel={fullNumber(blast.records_at_risk)} />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Modelled exposure"
            value={blast.estimated_exposure_display}
            sublabel="Planning estimate"
            accent="var(--color-escalating)"
          />
        </Panel>
        <Panel className="px-4 py-3">
          <Stat
            label="Lateral reach"
            value={String(blast.lateral_reach.estimated_additional_systems)}
            sublabel={`${blast.lateral_reach.credential_assets_reached} credential store(s)`}
          />
        </Panel>
      </div>

      <Panel>
        <div className="border-b border-[--color-border-subtle] px-5 py-3">
          <h3 className="text-sm font-semibold">Topological reach</h3>
          <p className="mt-0.5 text-xs text-[--color-ink-muted]">
            Assets this identity actually touched, grouped by category. Hover to isolate a subgraph.
          </p>
        </div>
        <BlastGraph blast={blast} />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <div className="border-b border-[--color-border-subtle] px-5 py-3">
            <h3 className="text-sm font-semibold">Regulatory exposure</h3>
            <p className="mt-0.5 text-xs text-[--color-ink-muted]">
              Derived from the classification of assets touched. An engineering assessment to route
              the question — not legal advice.
            </p>
          </div>
          {blast.compliance_impacts.length === 0 ? (
            <p className="px-5 py-8 text-center text-xs text-[--color-ink-muted]">
              No regulatory thresholds crossed.
            </p>
          ) : (
            <ul className="divide-y divide-[--color-border-subtle]">
              {blast.compliance_impacts.map((impact, i) => (
                <li key={i} className="px-5 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-xs font-semibold">{impact.framework}</p>
                    <Badge
                      className={cn(
                        'shrink-0 py-0 text-[9px]',
                        impact.severity === 'CRITICAL'
                          ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                          : 'border-orange-500/30 bg-orange-500/10 text-orange-300',
                      )}
                    >
                      {impact.severity}
                    </Badge>
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-[--color-ink-muted]">{impact.obligation}</p>
                  {impact.in_scope_assets.length > 0 && (
                    <p className="mt-1.5 text-[10px] text-[--color-ink-faint]">
                      In scope: {impact.in_scope_assets.join(', ')}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel>
          <div className="border-b border-[--color-border-subtle] px-5 py-3">
            <h3 className="text-sm font-semibold">Assets touched</h3>
            <p className="mt-0.5 text-xs text-[--color-ink-muted]">Ordered by sensitivity tier</p>
          </div>
          <div className="max-h-96 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[--color-surface]">
                <tr className="border-b border-[--color-border-subtle] text-left text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                  <th className="px-5 py-2 font-medium">Asset</th>
                  <th className="py-2 font-medium">Tier</th>
                  <th className="py-2 font-medium">Owner</th>
                  <th className="px-5 py-2 text-right font-medium">Records</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[--color-border-subtle]">
                {blast.asset_breakdown.map((asset) => (
                  <tr key={asset.key} className="hover:bg-white/[0.02]">
                    <td className="max-w-[14rem] px-5 py-2">
                      <p className="truncate font-medium" title={asset.name}>
                        {asset.name}
                      </p>
                      <p className="flex items-center gap-1.5 text-[10px] text-[--color-ink-faint]">
                        {asset.category}
                        {asset.crown_jewel && <span className="text-rose-400">· crown jewel</span>}
                        {asset.pii && <span className="text-amber-400">· PII</span>}
                        {asset.cardholder && <span className="text-orange-400">· PCI</span>}
                      </p>
                    </td>
                    <td className="py-2">
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[10px]',
                          asset.sensitivity >= 5
                            ? 'bg-rose-500/15 text-rose-300'
                            : asset.sensitivity >= 4
                              ? 'bg-orange-500/15 text-orange-300'
                              : 'bg-white/8 text-[--color-ink-muted]',
                        )}
                        title={SENSITIVITY_LABELS[asset.sensitivity]}
                      >
                        T{asset.sensitivity}
                      </span>
                    </td>
                    <td className="py-2 text-[--color-ink-muted]">{asset.owner_team}</td>
                    <td className="numeric px-5 py-2 text-right text-[--color-ink-muted]">
                      {asset.records ? compactNumber(asset.records) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  )
}

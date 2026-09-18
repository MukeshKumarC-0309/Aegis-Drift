import { useState } from 'react'
import { useAssetSummary, useAssets, useIndicators } from '@/lib/queries'
import { Badge, EmptyState, ErrorState, Input, Panel, PanelHeader, Select, Skeleton, Stat, Tabs } from '@/components/ui'
import { Pagination } from '@/components/ui/pagination'
import { compactNumber, relativeTime, SENSITIVITY_LABELS, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'

export function CatalogPage() {
  const [tab, setTab] = useState<'assets' | 'intel'>('assets')

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Catalogue</h1>
        <p className="mt-0.5 text-xs text-[--color-ink-muted]">
          What the platform protects, and the indicators it watches for. Asset classification is what
          turns a risk score into a quantified blast radius.
        </p>
      </header>

      <Panel>
        <Tabs
          tabs={[
            { id: 'assets', label: 'Protected assets' },
            { id: 'intel', label: 'Threat intelligence' },
          ]}
          active={tab}
          onChange={setTab}
          className="px-2"
        />
        <div className="p-0">{tab === 'assets' ? <AssetsTab /> : <IntelTab />}</div>
      </Panel>
    </div>
  )
}

function AssetsTab() {
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [crownOnly, setCrownOnly] = useState(false)
  const [page, setPage] = useState(1)

  const { data, isLoading, error, refetch } = useAssets({
    page,
    page_size: 25,
    search: search || undefined,
    category: category || undefined,
    crown_jewels_only: crownOnly || undefined,
  })
  const { data: summary } = useAssetSummary()
  const s = summary as
    | { total: number; crown_jewels: number; pii_assets: number; total_records: number; by_category: Record<string, number> }
    | undefined

  return (
    <div>
      <div className="grid grid-cols-2 gap-3 border-b border-[--color-border-subtle] p-4 lg:grid-cols-4">
        <Stat label="Assets" value={String(s?.total ?? 0)} />
        <Stat label="Crown jewels" value={String(s?.crown_jewels ?? 0)} accent="var(--color-critical)" />
        <Stat label="PII-bearing" value={String(s?.pii_assets ?? 0)} accent="var(--color-drift)" />
        <Stat label="Records" value={compactNumber(s?.total_records ?? 0)} />
      </div>

      <div className="grid gap-2 border-b border-[--color-border-subtle] p-3 sm:grid-cols-3">
        <Input
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1) }}
          placeholder="Search assets…"
        />
        <Select value={category} onChange={(e) => { setCategory(e.target.value); setPage(1) }}>
          <option value="">All categories</option>
          {Object.keys(s?.by_category ?? {}).map((c) => (
            <option key={c} value={c}>
              {titleise(c)}
            </option>
          ))}
        </Select>
        <label className="flex items-center gap-2 text-xs text-[--color-ink-muted]">
          <input
            type="checkbox"
            checked={crownOnly}
            onChange={(e) => { setCrownOnly(e.target.checked); setPage(1) }}
            className="accent-cyan-400"
          />
          Crown jewels only
        </label>
      </div>

      {isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      ) : error ? (
        <ErrorState error={error} retry={() => void refetch()} />
      ) : !data?.items.length ? (
        <EmptyState title="No assets match" />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[--color-border-subtle] text-left text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                  <th className="px-5 py-2.5 font-medium">Asset</th>
                  <th className="py-2.5 font-medium">Tier</th>
                  <th className="py-2.5 font-medium">Owner</th>
                  <th className="py-2.5 font-medium">Environment</th>
                  <th className="py-2.5 font-medium">Classification</th>
                  <th className="px-5 py-2.5 text-right font-medium">Records</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[--color-border-subtle]">
                {data.items.map((asset) => (
                  <tr key={asset.id} className="hover:bg-white/[0.02]">
                    <td className="px-5 py-2.5">
                      <p className="text-xs font-medium">{asset.display_name}</p>
                      <p className="font-mono text-[10px] text-[--color-ink-faint]">{asset.key}</p>
                    </td>
                    <td className="py-2.5">
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[10px]',
                          asset.sensitivity_level >= 5
                            ? 'bg-rose-500/15 text-rose-300'
                            : asset.sensitivity_level >= 4
                              ? 'bg-orange-500/15 text-orange-300'
                              : asset.sensitivity_level >= 3
                                ? 'bg-amber-500/15 text-amber-300'
                                : 'bg-white/8 text-[--color-ink-muted]',
                        )}
                        title={SENSITIVITY_LABELS[asset.sensitivity_level]}
                      >
                        T{asset.sensitivity_level}
                      </span>
                    </td>
                    <td className="py-2.5 text-xs text-[--color-ink-muted]">{asset.owner_team}</td>
                    <td className="py-2.5 text-xs text-[--color-ink-muted]">{asset.environment}</td>
                    <td className="py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {asset.is_crown_jewel && (
                          <Badge className="border-rose-500/30 bg-rose-500/10 py-0 text-[9px] text-rose-300">
                            crown jewel
                          </Badge>
                        )}
                        {asset.contains_pii && (
                          <Badge className="border-amber-500/30 bg-amber-500/10 py-0 text-[9px] text-amber-300">
                            PII
                          </Badge>
                        )}
                        {asset.contains_cardholder_data && (
                          <Badge className="border-orange-500/30 bg-orange-500/10 py-0 text-[9px] text-orange-300">
                            PCI
                          </Badge>
                        )}
                        {asset.contains_phi && (
                          <Badge className="border-violet-500/30 bg-violet-500/10 py-0 text-[9px] text-violet-300">
                            PHI
                          </Badge>
                        )}
                        {asset.compliance_scopes.map((scope) => (
                          <Badge key={scope} className="py-0 text-[9px]">
                            {scope}
                          </Badge>
                        ))}
                      </div>
                    </td>
                    <td className="numeric px-5 py-2.5 text-right text-xs text-[--color-ink-muted]">
                      {asset.record_estimate ? compactNumber(asset.record_estimate) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination meta={data.meta} onPage={setPage} />
        </>
      )}
    </div>
  )
}

function IntelTab() {
  const { data, isLoading, error, refetch } = useIndicators({ page_size: 50 })

  return (
    <div>
      <PanelHeader
        title="Indicators of compromise"
        subtitle="Matches against an event's network artefacts feed the threat-intel vector."
      />
      {isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      ) : error ? (
        <ErrorState error={error} retry={() => void refetch()} />
      ) : !data?.items.length ? (
        <EmptyState title="No indicators" description="The intel feed is empty." />
      ) : (
        <ul className="divide-y divide-[--color-border-subtle]">
          {data.items.map((indicator) => (
            <li key={indicator.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
              <Badge className="shrink-0 py-0 text-[9px]">{indicator.indicator_type}</Badge>
              <span className="font-mono text-xs">{indicator.value}</span>
              <span className="flex-1 truncate text-[11px] text-[--color-ink-muted]">
                {indicator.description}
              </span>
              <span className="shrink-0 text-[10px] text-[--color-ink-faint]">{indicator.source_feed}</span>
              <div className="w-20 shrink-0">
                <div className="h-1 overflow-hidden rounded-full bg-white/8">
                  <div
                    className={cn(
                      'h-full rounded-full',
                      indicator.confidence >= 85 ? 'bg-rose-400' : indicator.confidence >= 65 ? 'bg-amber-400' : 'bg-slate-400',
                    )}
                    style={{ width: `${indicator.confidence}%` }}
                  />
                </div>
                <p className="numeric mt-0.5 text-right text-[9px] text-[--color-ink-faint]">
                  {indicator.confidence}%
                </p>
              </div>
              <span className="w-20 shrink-0 text-right text-[10px] text-[--color-ink-faint]">
                {relativeTime(indicator.last_seen)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

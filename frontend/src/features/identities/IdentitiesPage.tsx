import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useDepartments, useIdentities } from '@/lib/queries'
import { Badge, Button, EmptyState, ErrorState, Input, Panel, Select, Skeleton } from '@/components/ui'
import { RiskDial, StateBadge, VelocityIndicator } from '@/features/dashboard/CommandCenter'
import { Pagination } from '@/components/ui/pagination'
import { relativeTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { TransitionState } from '@/types/api'

const STATES: TransitionState[] = ['CRITICAL_TRANSITION', 'ESCALATING', 'EARLY_DRIFT', 'STABLE']

export function IdentitiesPage() {
  const [search, setSearch] = useState('')
  const [department, setDepartment] = useState('')
  const [state, setState] = useState('')
  const [privilegedOnly, setPrivilegedOnly] = useState(false)
  const [watchlistOnly, setWatchlistOnly] = useState(false)
  const [page, setPage] = useState(1)

  const params = {
    page,
    page_size: 25,
    search: search || undefined,
    department: department || undefined,
    state: state || undefined,
    privileged_only: privilegedOnly || undefined,
    watchlist_only: watchlistOnly || undefined,
    sort_by: 'risk_score',
    sort_dir: 'desc',
  }

  const { data, isLoading, error, refetch, isFetching } = useIdentities(params)
  const { data: departments } = useDepartments()

  const reset = () => {
    setSearch('')
    setDepartment('')
    setState('')
    setPrivilegedOnly(false)
    setWatchlistOnly(false)
    setPage(1)
  }

  const filtered = Boolean(search || department || state || privilegedOnly || watchlistOnly)

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Identities</h1>
          <p className="mt-0.5 text-xs text-[--color-ink-muted]">
            {data ? `${data.meta.total} monitored identities` : 'Loading the estate…'}
          </p>
        </div>
        {filtered && (
          <Button size="sm" variant="ghost" onClick={reset}>
            Clear filters
          </Button>
        )}
      </header>

      <Panel className="p-3">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            placeholder="Search name, username, role…"
            className="lg:col-span-2"
          />
          <Select
            value={department}
            onChange={(e) => {
              setDepartment(e.target.value)
              setPage(1)
            }}
          >
            <option value="">All departments</option>
            {(departments ?? []).map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </Select>
          <Select
            value={state}
            onChange={(e) => {
              setState(e.target.value)
              setPage(1)
            }}
          >
            <option value="">All states</option>
            {STATES.map((s) => (
              <option key={s} value={s}>
                {titleise(s)}
              </option>
            ))}
          </Select>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant={privilegedOnly ? 'primary' : 'subtle'}
              onClick={() => {
                setPrivilegedOnly((v) => !v)
                setPage(1)
              }}
              className="flex-1"
            >
              Privileged
            </Button>
            <Button
              size="sm"
              variant={watchlistOnly ? 'primary' : 'subtle'}
              onClick={() => {
                setWatchlistOnly((v) => !v)
                setPage(1)
              }}
              className="flex-1"
            >
              Watchlist
            </Button>
          </div>
        </div>
      </Panel>

      <Panel>
        {isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className="h-14" />
            ))}
          </div>
        ) : error ? (
          <ErrorState error={error} retry={() => void refetch()} />
        ) : !data?.items.length ? (
          <EmptyState
            title="No identities match"
            description="Adjust the filters, or clear them to see the whole estate."
            action={
              filtered ? (
                <Button size="sm" onClick={reset}>
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[--color-border-subtle] text-left text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
                    <th className="px-5 py-2.5 font-medium">Identity</th>
                    <th className="py-2.5 font-medium">Department</th>
                    <th className="py-2.5 font-medium">State</th>
                    <th className="py-2.5 font-medium">Dominant vector</th>
                    <th className="py-2.5 text-right font-medium">Velocity</th>
                    <th className="py-2.5 font-medium">Last event</th>
                    <th className="px-5 py-2.5 text-right font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody className={cn('divide-y divide-[--color-border-subtle]', isFetching && 'opacity-60')}>
                  {data.items.map((identity) => (
                    <tr key={identity.id} className="group transition-colors hover:bg-white/[0.02]">
                      <td className="px-5 py-3">
                        <Link to={`/investigate/${identity.username}`} className="block">
                          <div className="flex items-center gap-2">
                            <span className="font-medium group-hover:text-cyan-200">
                              {identity.display_name}
                            </span>
                            {identity.is_privileged && (
                              <Badge className="border-amber-500/30 bg-amber-500/10 py-0 text-[9px] text-amber-300">
                                priv
                              </Badge>
                            )}
                            {identity.is_quarantined && (
                              <Badge className="border-rose-500/30 bg-rose-500/10 py-0 text-[9px] text-rose-300">
                                quarantined
                              </Badge>
                            )}
                            {identity.on_watchlist && (
                              <Badge className="border-amber-500/30 bg-amber-500/10 py-0 text-[9px] text-amber-300">
                                watchlist
                              </Badge>
                            )}
                            {identity.is_service_account && (
                              <Badge className="py-0 text-[9px]">service</Badge>
                            )}
                          </div>
                          <p className="font-mono text-[11px] text-[--color-ink-faint]">
                            @{identity.username} · {identity.role_title}
                          </p>
                        </Link>
                      </td>
                      <td className="py-3 text-xs text-[--color-ink-muted]">{identity.department}</td>
                      <td className="py-3">
                        <StateBadge state={identity.transition_state} />
                      </td>
                      <td className="py-3 text-xs text-[--color-ink-muted]">
                        {titleise(identity.dominant_vector)}
                      </td>
                      <td className="py-3 text-right">
                        <VelocityIndicator velocity={identity.drift_velocity} />
                      </td>
                      <td className="py-3 text-xs text-[--color-ink-faint]">
                        {relativeTime(identity.last_event_at)}
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex justify-end">
                          <RiskDial score={identity.risk_score} size={34} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination meta={data.meta} onPage={setPage} />
          </>
        )}
      </Panel>
    </div>
  )
}

import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '@/lib/auth'
import { useLiveStore } from '@/lib/live'
import { useAlertStats } from '@/lib/queries'
import { cn } from '@/lib/utils'
import { Badge, Button } from '@/components/ui'
import {
  IconAlert,
  IconChart,
  IconDatabase,
  IconFlask,
  IconFolder,
  IconGauge,
  IconLogout,
  IconRadar,
  IconSettings,
  IconShield,
  IconUsers,
} from '@/components/ui/icons'
import { CommandPalette } from '@/components/layout/CommandPalette'
import { LiveFeedRail } from '@/components/layout/LiveFeedRail'

interface NavItem {
  to: string
  label: string
  icon: (p: { className?: string }) => ReactNode
  group: string
  badgeKey?: 'open'
}

const NAV: NavItem[] = [
  { to: '/', label: 'Command Center', icon: IconGauge, group: 'Monitor' },
  { to: '/identities', label: 'Identities', icon: IconUsers, group: 'Monitor' },
  { to: '/alerts', label: 'Triage Queue', icon: IconAlert, group: 'Monitor', badgeKey: 'open' },
  { to: '/cases', label: 'Cases', icon: IconFolder, group: 'Respond' },
  { to: '/response', label: 'Playbooks', icon: IconShield, group: 'Respond' },
  { to: '/detections', label: 'Detections', icon: IconRadar, group: 'Configure' },
  { to: '/contexts', label: 'Context Registry', icon: IconShield, group: 'Configure' },
  { to: '/catalog', label: 'Asset Catalogue', icon: IconDatabase, group: 'Configure' },
  { to: '/simulator', label: 'Threat Simulator', icon: IconFlask, group: 'Operate' },
  { to: '/executive', label: 'Executive View', icon: IconChart, group: 'Operate' },
  { to: '/settings', label: 'Settings', icon: IconSettings, group: 'Operate' },
]

const GROUPS = ['Monitor', 'Respond', 'Configure', 'Operate']

export function AppShell() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const { status, connect, disconnect } = useLiveStore()
  const { data: alertStats } = useAlertStats()
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [railOpen, setRailOpen] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  useEffect(() => {
    connect()
    return () => disconnect()
  }, [connect, disconnect])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => setMobileNavOpen(false), [location.pathname])

  const openAlerts = (alertStats as { open?: number } | undefined)?.open ?? 0

  return (
    <div className="flex min-h-screen bg-[--color-void]">
      {/* ------------------------------------------------------------ sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-[--color-border-subtle] bg-[--color-surface] transition-transform lg:static lg:translate-x-0',
          mobileNavOpen ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-14 items-center gap-2.5 border-b border-[--color-border-subtle] px-4">
          <div className="flex size-7 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400 to-indigo-600">
            <IconShield className="size-4 text-white" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold tracking-tight">SilentShift</p>
            <p className="text-[10px] tracking-wider text-[--color-ink-faint] uppercase">ITDR Console</p>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-2.5 py-3">
          {GROUPS.map((group) => (
            <div key={group} className="mb-4">
              <p className="mb-1.5 px-2.5 text-[10px] font-semibold tracking-wider text-[--color-ink-faint] uppercase">
                {group}
              </p>
              <div className="space-y-0.5">
                {NAV.filter((item) => item.group === group).map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.to === '/'}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-medium transition-colors',
                        isActive
                          ? 'bg-cyan-500/10 text-cyan-200'
                          : 'text-[--color-ink-muted] hover:bg-white/5 hover:text-[--color-ink]',
                      )
                    }
                  >
                    <item.icon className="size-4 shrink-0" />
                    <span className="flex-1 truncate">{item.label}</span>
                    {item.badgeKey === 'open' && openAlerts > 0 && (
                      <span className="numeric rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-rose-300">
                        {openAlerts}
                      </span>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-[--color-border-subtle] p-3">
          <div className="mb-2 flex items-center gap-2.5 rounded-lg px-2 py-1.5">
            <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-slate-600 to-slate-800 text-[11px] font-semibold">
              {user?.full_name?.charAt(0) ?? '?'}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium">{user?.full_name}</p>
              <p className="truncate text-[10px] text-[--color-ink-faint] capitalize">{user?.role}</p>
            </div>
            <button
              onClick={() => {
                signOut()
                navigate('/login')
              }}
              aria-label="Sign out"
              className="rounded p-1 text-[--color-ink-faint] transition-colors hover:bg-white/5 hover:text-rose-300"
            >
              <IconLogout className="size-4" />
            </button>
          </div>
        </div>
      </aside>

      {mobileNavOpen && (
        <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setMobileNavOpen(false)} />
      )}

      {/* --------------------------------------------------------------- main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-[--color-border-subtle] bg-[--color-surface]/85 px-4 backdrop-blur-xl">
          <button
            onClick={() => setMobileNavOpen((v) => !v)}
            aria-label="Toggle navigation"
            className="rounded-lg p-1.5 text-[--color-ink-muted] hover:bg-white/5 lg:hidden"
          >
            <svg className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 12h18M3 6h18M3 18h18" />
            </svg>
          </button>

          <button
            onClick={() => setPaletteOpen(true)}
            className="flex h-8 flex-1 max-w-sm items-center gap-2 rounded-lg border border-[--color-border] bg-[--color-surface-raised] px-3 text-xs text-[--color-ink-faint] transition-colors hover:border-[--color-border-strong]"
          >
            <svg className="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.3-4.3" />
            </svg>
            <span className="flex-1 text-left">Search identities, cases, actions…</span>
            <kbd className="rounded border border-[--color-border] bg-[--color-surface] px-1.5 py-0.5 text-[10px]">
              ⌘K
            </kbd>
          </button>

          <div className="ml-auto flex items-center gap-2">
            <Badge
              dot={cn(
                status === 'open' ? 'bg-emerald-400 animate-pulse-ring' : status === 'connecting' ? 'bg-amber-400' : 'bg-slate-500',
              )}
              title={
                status === 'open'
                  ? 'Live telemetry stream connected'
                  : status === 'connecting'
                    ? 'Connecting to the live stream'
                    : 'Live stream disconnected — reconnecting automatically'
              }
              className="hidden sm:inline-flex"
            >
              {status === 'open' ? 'Live' : status === 'connecting' ? 'Connecting' : 'Offline'}
            </Badge>
            <Button size="sm" variant="ghost" onClick={() => setRailOpen((v) => !v)}>
              Activity
            </Button>
          </div>
        </header>

        <main className="min-w-0 flex-1 p-4 lg:p-6">
          <Outlet />
        </main>
      </div>

      <LiveFeedRail open={railOpen} onClose={() => setRailOpen(false)} />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  )
}

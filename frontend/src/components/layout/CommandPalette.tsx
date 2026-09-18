import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useIdentities } from '@/lib/queries'
import { cn } from '@/lib/utils'
import { riskTextClass } from '@/lib/format'

interface Command {
  id: string
  label: string
  hint?: string
  group: string
  run: () => void
  score?: number
}

const ROUTES: { label: string; path: string; hint: string }[] = [
  { label: 'Command Center', path: '/', hint: 'Fleet posture and KPIs' },
  { label: 'Identities', path: '/identities', hint: 'The monitored estate' },
  { label: 'Triage Queue', path: '/alerts', hint: 'Open alerts' },
  { label: 'Cases', path: '/cases', hint: 'Investigations' },
  { label: 'Playbooks', path: '/response', hint: 'Automated response' },
  { label: 'Detections', path: '/detections', hint: 'Rule authoring and tuning' },
  { label: 'Context Registry', path: '/contexts', hint: 'Approved business justifications' },
  { label: 'Asset Catalogue', path: '/catalog', hint: 'Protected assets and threat intel' },
  { label: 'Threat Simulator', path: '/simulator', hint: 'Run attack scenarios' },
  { label: 'Executive View', path: '/executive', hint: 'Programme effectiveness' },
  { label: 'Settings', path: '/settings', hint: 'Engine tuning and audit trail' },
]

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  // Only fetch identities once the palette is open, and only when actually searching.
  const { data: identityPage } = useIdentities(
    open && query.length >= 2 ? { search: query, page_size: 6 } : { page_size: 6 },
  )

  useEffect(() => {
    if (open) {
      setQuery('')
      setCursor(0)
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [open])

  const commands = useMemo<Command[]>(() => {
    const q = query.trim().toLowerCase()
    const list: Command[] = []

    for (const route of ROUTES) {
      if (!q || route.label.toLowerCase().includes(q) || route.hint.toLowerCase().includes(q)) {
        list.push({
          id: `route:${route.path}`,
          label: route.label,
          hint: route.hint,
          group: 'Navigate',
          run: () => navigate(route.path),
        })
      }
    }

    if (q.length >= 2) {
      for (const identity of identityPage?.items ?? []) {
        list.push({
          id: `identity:${identity.id}`,
          label: identity.username,
          hint: `${identity.role_title} · ${identity.department} · risk ${identity.risk_score.toFixed(0)}`,
          group: 'Investigate',
          score: identity.risk_score,
          run: () => navigate(`/investigate/${identity.username}`),
        })
      }
    }

    return list
  }, [query, identityPage, navigate])

  useEffect(() => {
    setCursor((c) => Math.min(c, Math.max(0, commands.length - 1)))
  }, [commands.length])

  if (!open) return null

  const select = (command: Command) => {
    command.run()
    onClose()
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') return onClose()
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setCursor((c) => (c + 1) % Math.max(commands.length, 1))
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      setCursor((c) => (c - 1 + commands.length) % Math.max(commands.length, 1))
    }
    if (e.key === 'Enter' && commands[cursor]) {
      e.preventDefault()
      select(commands[cursor])
    }
  }

  const groups = [...new Set(commands.map((c) => c.group))]

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[12vh]">
      <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} role="presentation" />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="panel-raised animate-slide-up relative w-full max-w-xl overflow-hidden shadow-2xl"
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-2.5 border-b border-[--color-border-subtle] px-4">
          <svg className="size-4 text-[--color-ink-faint]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.3-4.3" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setCursor(0)
            }}
            placeholder="Jump to a page, or search an identity by name…"
            className="h-12 flex-1 bg-transparent text-sm text-[--color-ink] placeholder:text-[--color-ink-faint] focus:outline-none"
          />
          <kbd className="rounded border border-[--color-border] px-1.5 py-0.5 text-[10px] text-[--color-ink-faint]">
            esc
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto py-2">
          {commands.length === 0 ? (
            <p className="px-4 py-8 text-center text-xs text-[--color-ink-muted]">
              Nothing matches “{query}”.
            </p>
          ) : (
            groups.map((group) => (
              <div key={group} className="mb-1">
                <p className="px-4 py-1 text-[10px] font-semibold tracking-wider text-[--color-ink-faint] uppercase">
                  {group}
                </p>
                {commands
                  .map((command, index) => ({ command, index }))
                  .filter(({ command }) => command.group === group)
                  .map(({ command, index }) => (
                    <button
                      key={command.id}
                      onMouseEnter={() => setCursor(index)}
                      onClick={() => select(command)}
                      className={cn(
                        'flex w-full items-center gap-3 px-4 py-2 text-left transition-colors',
                        cursor === index ? 'bg-cyan-500/10' : 'hover:bg-white/5',
                      )}
                    >
                      <span className="flex-1 truncate text-sm">{command.label}</span>
                      {command.score !== undefined && (
                        <span className={cn('numeric text-xs', riskTextClass(command.score))}>
                          {command.score.toFixed(0)}
                        </span>
                      )}
                      <span className="hidden truncate text-xs text-[--color-ink-faint] sm:block">
                        {command.hint}
                      </span>
                    </button>
                  ))}
              </div>
            ))
          )}
        </div>

        <div className="flex items-center gap-3 border-t border-[--color-border-subtle] px-4 py-2 text-[10px] text-[--color-ink-faint]">
          <span>↑↓ navigate</span>
          <span>↵ open</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  )
}

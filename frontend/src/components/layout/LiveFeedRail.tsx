import { useLiveStore } from '@/lib/live'
import { cn } from '@/lib/utils'
import { relativeTime, titleise } from '@/lib/format'
import { Button, EmptyState } from '@/components/ui'
import { IconPulse, IconX } from '@/components/ui/icons'

/** Visual treatment per live-event type, so the rail can be skimmed by colour. */
const EVENT_STYLE: Record<string, { dot: string; label: string }> = {
  'event.ingested': { dot: 'bg-slate-400', label: 'Telemetry' },
  'identity.rescored': { dot: 'bg-cyan-400', label: 'Rescored' },
  'action.executed': { dot: 'bg-indigo-400', label: 'Response' },
  'case.created': { dot: 'bg-violet-400', label: 'Case' },
  'scenario.completed': { dot: 'bg-amber-400', label: 'Scenario' },
  'fleet.rescored': { dot: 'bg-emerald-400', label: 'Fleet' },
  'estate.reset': { dot: 'bg-rose-400', label: 'Reset' },
  connected: { dot: 'bg-emerald-400', label: 'Connected' },
}

function describe(type: string, payload: Record<string, unknown>): string {
  switch (type) {
    case 'event.ingested':
      return `${payload.action} on ${payload.resource}`
    case 'identity.rescored':
      return `${payload.username} → ${Number(payload.risk_score ?? 0).toFixed(0)} (${titleise(
        String(payload.transition_state ?? ''),
      )})`
    case 'action.executed':
      return `${titleise(String(payload.action ?? ''))} on ${payload.username}`
    case 'case.created':
      return `${payload.reference} — ${payload.title}`
    case 'scenario.completed':
      return `${payload.scenario_id} → ${titleise(String(payload.state_after ?? ''))}`
    case 'fleet.rescored':
      return `${payload.scored} identities scored, ${payload.escalated} escalating`
    case 'estate.reset':
      return 'Estate reset to its seeded baseline'
    case 'connected':
      return `Stream open as ${payload.user}`
    default:
      return JSON.stringify(payload).slice(0, 90)
  }
}

export function LiveFeedRail({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { events, status, clear } = useLiveStore()

  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/50 xl:hidden" onClick={onClose} />}
      <aside
        className={cn(
          'fixed inset-y-0 right-0 z-40 flex w-80 flex-col border-l border-[--color-border-subtle] bg-[--color-surface] transition-transform',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
        aria-hidden={!open}
      >
        <div className="flex h-14 items-center gap-2 border-b border-[--color-border-subtle] px-4">
          <IconPulse className="size-4 text-[--color-accent]" />
          <h2 className="flex-1 text-sm font-semibold">Live activity</h2>
          <Button size="sm" variant="ghost" onClick={clear}>
            Clear
          </Button>
          <button
            onClick={onClose}
            aria-label="Close activity rail"
            className="rounded p-1 text-[--color-ink-faint] hover:bg-white/5 hover:text-[--color-ink]"
          >
            <IconX className="size-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {events.length === 0 ? (
            <EmptyState
              title={status === 'open' ? 'Listening' : 'Stream offline'}
              description={
                status === 'open'
                  ? 'Scoring results, response actions and telemetry appear here as they happen.'
                  : 'Reconnecting automatically with exponential backoff.'
              }
            />
          ) : (
            <ul className="divide-y divide-[--color-border-subtle]">
              {events.map((event, index) => {
                const style = EVENT_STYLE[event.type] ?? { dot: 'bg-slate-500', label: event.type }
                return (
                  <li key={`${event.at}-${index}`} className="flex gap-2.5 px-4 py-2.5">
                    <span className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', style.dot)} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="text-[11px] font-medium text-[--color-ink-muted]">{style.label}</span>
                        <span className="shrink-0 text-[10px] text-[--color-ink-faint]">
                          {event.at ? relativeTime(event.at) : 'now'}
                        </span>
                      </div>
                      <p className="mt-0.5 truncate text-xs text-[--color-ink]" title={describe(event.type, event.payload)}>
                        {describe(event.type, event.payload)}
                      </p>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      </aside>
    </>
  )
}

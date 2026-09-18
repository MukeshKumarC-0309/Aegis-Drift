/**
 * Live WebSocket feed with bounded reconnection.
 *
 * Kept in a Zustand store rather than React state so any component can read the
 * feed without prop drilling, and so a route change never tears down the socket.
 */

import { create } from 'zustand'
import { tokenStore } from '@/lib/api'
import type { LiveEvent } from '@/types/api'

const MAX_BUFFER = 150
const MAX_BACKOFF_MS = 30_000

type Status = 'idle' | 'connecting' | 'open' | 'closed'

interface LiveStore {
  status: Status
  events: LiveEvent[]
  lastMessageAt: number | null
  connect: () => void
  disconnect: () => void
  clear: () => void
}

let socket: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null
let attempt = 0
let intentionallyClosed = false

export const useLiveStore = create<LiveStore>((set, get) => ({
  status: 'idle',
  events: [],
  lastMessageAt: null,

  connect: () => {
    const token = tokenStore.access
    if (!token || socket) return

    intentionallyClosed = false
    set({ status: 'connecting' })

    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${scheme}://${window.location.host}/api/v1/stream/live?token=${encodeURIComponent(token)}`

    try {
      socket = new WebSocket(url)
    } catch {
      set({ status: 'closed' })
      return
    }

    socket.onopen = () => {
      attempt = 0
      set({ status: 'open' })
    }

    socket.onmessage = (raw) => {
      try {
        const message = JSON.parse(raw.data) as LiveEvent
        if (message.type === 'heartbeat') {
          set({ lastMessageAt: Date.now() })
          return
        }
        set((state) => ({
          // Newest first, bounded — an unbounded feed would leak on a long shift.
          events: [message, ...state.events].slice(0, MAX_BUFFER),
          lastMessageAt: Date.now(),
        }))
      } catch {
        /* ignore malformed frames */
      }
    }

    socket.onclose = () => {
      socket = null
      set({ status: 'closed' })
      if (intentionallyClosed || !tokenStore.access) return

      // Exponential backoff with jitter, so a server restart does not produce a
      // synchronised reconnect storm from every open console.
      attempt += 1
      const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** attempt) * (0.7 + Math.random() * 0.6)
      reconnectTimer = setTimeout(() => get().connect(), delay)
    }

    socket.onerror = () => socket?.close()
  },

  disconnect: () => {
    intentionallyClosed = true
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    socket?.close()
    socket = null
    attempt = 0
    set({ status: 'idle' })
  },

  clear: () => set({ events: [] }),
}))

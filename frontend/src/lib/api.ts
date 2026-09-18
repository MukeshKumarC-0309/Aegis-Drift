/**
 * Typed API client.
 *
 * Owns token storage and transparent refresh: a 401 triggers exactly one refresh
 * attempt, and concurrent 401s share that single in-flight refresh rather than
 * stampeding the endpoint.
 */

import type { Page, TokenPair } from '@/types/api'

const BASE = import.meta.env.VITE_API_BASE_URL ?? ''
const API = `${BASE}/api/v1`

const ACCESS_KEY = 'silentshift.access'
const REFRESH_KEY = 'silentshift.refresh'

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'ApiError'
  }

  /** Field-level messages from a 422, flattened for form display. */
  get fieldErrors(): string[] {
    const fields = this.details?.fields
    if (!Array.isArray(fields)) return []
    return fields.map((f: { location?: string; message?: string }) =>
      f.location ? `${f.location}: ${f.message}` : String(f.message),
    )
  }
}

export const tokenStore = {
  get access() {
    return localStorage.getItem(ACCESS_KEY)
  },
  get refresh() {
    return localStorage.getItem(REFRESH_KEY)
  },
  set(pair: TokenPair) {
    localStorage.setItem(ACCESS_KEY, pair.access_token)
    localStorage.setItem(REFRESH_KEY, pair.refresh_token)
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY)
    localStorage.removeItem(REFRESH_KEY)
  },
}

type Listener = () => void
const unauthorizedListeners = new Set<Listener>()

/** Notified when refresh fails and the session is genuinely over. */
export function onUnauthorized(listener: Listener) {
  unauthorizedListeners.add(listener)
  return () => unauthorizedListeners.delete(listener)
}

let refreshInFlight: Promise<boolean> | null = null

async function attemptRefresh(): Promise<boolean> {
  const token = tokenStore.refresh
  if (!token) return false

  refreshInFlight ??= (async () => {
    try {
      const res = await fetch(`${API}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: token }),
      })
      if (!res.ok) return false
      tokenStore.set((await res.json()) as TokenPair)
      return true
    } catch {
      return false
    } finally {
      // Release the gate on the next tick so racing callers see this result.
      setTimeout(() => {
        refreshInFlight = null
      }, 0)
    }
  })()

  return refreshInFlight
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
  query?: Record<string, string | number | boolean | undefined | null>
  raw?: boolean
  skipAuth?: boolean
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, query, raw, skipAuth, headers, ...rest } = options

  const url = new URL(`${API}${path}`, window.location.origin)
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value))
      }
    }
  }

  const send = async (): Promise<Response> =>
    fetch(url.toString(), {
      ...rest,
      headers: {
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(!skipAuth && tokenStore.access ? { Authorization: `Bearer ${tokenStore.access}` } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })

  let response = await send()

  if (response.status === 401 && !skipAuth) {
    if (await attemptRefresh()) {
      response = await send()
    } else {
      tokenStore.clear()
      unauthorizedListeners.forEach((fn) => fn())
    }
  }

  if (!response.ok) {
    let code = `http_${response.status}`
    let message = response.statusText || 'Request failed'
    let details: Record<string, unknown> | undefined
    try {
      const payload = await response.json()
      if (payload?.error) {
        code = payload.error.code ?? code
        message = payload.error.message ?? message
        details = payload.error.details
      } else if (payload?.detail) {
        message = typeof payload.detail === 'string' ? payload.detail : message
      }
    } catch {
      /* the body was not JSON — keep the status text */
    }
    throw new ApiError(response.status, code, message, details)
  }

  if (response.status === 204) return undefined as T
  if (raw) return (await response.text()) as T
  return (await response.json()) as T
}

export const api = {
  get: <T,>(path: string, query?: RequestOptions['query']) => request<T>(path, { query }),
  getRaw: (path: string) => request<string>(path, { raw: true }),
  post: <T,>(path: string, body?: unknown, query?: RequestOptions['query']) =>
    request<T>(path, { method: 'POST', body, query }),
  patch: <T,>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
  put: <T,>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
  delete: <T,>(path: string) => request<T>(path, { method: 'DELETE' }),
}

export async function login(email: string, password: string): Promise<TokenPair> {
  const pair = await request<TokenPair>('/auth/login', {
    method: 'POST',
    body: { email, password },
    skipAuth: true,
  })
  tokenStore.set(pair)
  return pair
}

export function logout() {
  tokenStore.clear()
}

/** Download a text response as a file without leaving the SPA. */
export async function downloadText(path: string, filename: string) {
  const content = await api.getRaw(path)
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
  const href = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = href
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(href)
}

export type { Page }

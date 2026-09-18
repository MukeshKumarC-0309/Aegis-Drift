import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, login as apiLogin, logout as apiLogout, onUnauthorized, tokenStore } from '@/lib/api'
import type { Role, User } from '@/types/api'

interface AuthState {
  user: User | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<void>
  signOut: () => void
  /** True when the signed-in user meets or exceeds the given role. */
  can: (minimum: Role) => boolean
}

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, responder: 2, admin: 3 }

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  const loadProfile = useCallback(async () => {
    if (!tokenStore.access) {
      setUser(null)
      setLoading(false)
      return
    }
    try {
      setUser(await api.get<User>('/auth/me'))
    } catch {
      tokenStore.clear()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadProfile()
    const unsubscribe = onUnauthorized(() => setUser(null))
    return () => {
      unsubscribe()
    }
  }, [loadProfile])

  const signIn = useCallback(async (email: string, password: string) => {
    await apiLogin(email, password)
    setUser(await api.get<User>('/auth/me'))
  }, [])

  const signOut = useCallback(() => {
    apiLogout()
    setUser(null)
  }, [])

  const can = useCallback(
    (minimum: Role) => (user ? RANK[user.role] >= RANK[minimum] : false),
    [user],
  )

  const value = useMemo(
    () => ({ user, loading, signIn, signOut, can }),
    [user, loading, signIn, signOut, can],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside an AuthProvider')
  return ctx
}

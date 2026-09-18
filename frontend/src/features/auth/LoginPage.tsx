import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '@/lib/auth'
import { ApiError } from '@/lib/api'
import { Button, Field, Input } from '@/components/ui'
import { IconShield } from '@/components/ui/icons'

/** Seeded demo operators, surfaced so an evaluator can see the RBAC tiers work. */
const DEMO_ACCOUNTS = [
  { role: 'Administrator', email: 'admin@aegisdrift.com', password: 'ChangeMe_Aeg1sDrift!', can: 'Everything, including engine tuning and estate reset' },
  { role: 'Analyst', email: 'analyst@aegisdrift.com', password: 'AnalystDemo_2026!', can: 'Triage, cases, rules and context records' },
  { role: 'Responder', email: 'responder@aegisdrift.com', password: 'ResponderDemo_2026!', can: 'Everything an analyst can do, plus containment actions' },
  { role: 'Viewer', email: 'viewer@aegisdrift.com', password: 'ViewerDemo_2026!', can: 'Read-only across the console' },
]

export function LoginPage() {
  const { user, signIn, loading } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState(DEMO_ACCOUNTS[0].email)
  const [password, setPassword] = useState(DEMO_ACCOUNTS[0].password)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (!loading && user) return <Navigate to="/" replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await signIn(email, password)
      navigate('/')
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : 'Could not reach the API. Check that the backend is running.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* -------------------------------------------------------- narrative */}
      <div className="grid-backdrop relative hidden flex-col justify-between overflow-hidden border-r border-[--color-border-subtle] bg-[--color-surface] p-10 lg:flex">
        <div className="pointer-events-none absolute -top-40 -left-40 size-[32rem] rounded-full bg-cyan-500/8 blur-3xl" />
        <div className="pointer-events-none absolute -right-32 -bottom-40 size-[28rem] rounded-full bg-indigo-500/8 blur-3xl" />

        <div className="relative flex items-center gap-3">
          <div className="flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-indigo-600">
            <IconShield className="size-5 text-white" />
          </div>
          <div>
            <p className="font-semibold tracking-tight">Aegis Drift</p>
            <p className="text-[11px] tracking-wider text-[--color-ink-faint] uppercase">
              Identity Threat Detection &amp; Response
            </p>
          </div>
        </div>

        <div className="relative max-w-md">
          <h1 className="text-3xl leading-tight font-semibold tracking-tight text-balance">
            The breach rarely announces itself.
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-[--color-ink-muted]">
            A compromised account behaves normally for weeks, then drifts. Each step clears every
            per-event threshold you have. Only the <em>sequence</em> gives it away.
          </p>
          <p className="mt-3 text-sm leading-relaxed text-[--color-ink-muted]">
            Aegis Drift learns what normal looks like for each identity, scores every event on eight
            behavioural dimensions, and accumulates that signal over time with exponential decay — so
            sustained drift compounds while isolated noise fades.
          </p>

          <dl className="mt-8 grid grid-cols-2 gap-x-6 gap-y-5">
            {[
              ['8', 'behavioural vectors per event'],
              ['48h', 'risk decay half-life'],
              ['12', 'built-in detections'],
              ['0', 'approvals that can hide tampering'],
            ].map(([value, label]) => (
              <div key={label}>
                <dt className="numeric text-2xl font-semibold text-cyan-300">{value}</dt>
                <dd className="mt-0.5 text-xs text-[--color-ink-muted]">{label}</dd>
              </div>
            ))}
          </dl>
        </div>

        <p className="relative text-[11px] text-[--color-ink-faint]">
          Demonstration estate — all identities, telemetry and incidents are synthetic.
        </p>
      </div>

      {/* ------------------------------------------------------------ form */}
      <div className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <div className="mb-3 flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-indigo-600">
              <IconShield className="size-5 text-white" />
            </div>
            <h1 className="text-lg font-semibold">Aegis Drift</h1>
            <p className="text-xs text-[--color-ink-muted]">Identity Threat Detection &amp; Response</p>
          </div>

          <h2 className="text-lg font-semibold tracking-tight">Sign in to the console</h2>
          <p className="mt-1 text-xs text-[--color-ink-muted]">
            Use one of the seeded operator accounts below.
          </p>

          <form onSubmit={submit} className="mt-6 space-y-4">
            <Field label="Email">
              <Input
                type="email"
                value={email}
                autoComplete="username"
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </Field>
            <Field label="Password">
              <Input
                type="password"
                value={password}
                autoComplete="current-password"
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Field>

            {error && (
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
                {error}
              </div>
            )}

            <Button type="submit" variant="primary" size="lg" loading={busy} className="w-full">
              Sign in
            </Button>
          </form>

          <div className="mt-8">
            <p className="mb-2 text-[11px] font-semibold tracking-wider text-[--color-ink-faint] uppercase">
              Demo accounts
            </p>
            <div className="space-y-1.5">
              {DEMO_ACCOUNTS.map((account) => (
                <button
                  key={account.email}
                  type="button"
                  onClick={() => {
                    setEmail(account.email)
                    setPassword(account.password)
                    setError(null)
                  }}
                  className="w-full rounded-lg border border-[--color-border-subtle] bg-[--color-surface] px-3 py-2 text-left transition-colors hover:border-[--color-border-strong]"
                >
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-medium">{account.role}</span>
                    <span className="font-mono text-[10px] text-[--color-ink-faint]">{account.email}</span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-[--color-ink-muted]">{account.can}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

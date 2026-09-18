import { Component, lazy, Suspense, type ReactNode } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApiError } from '@/lib/api'
import { AuthProvider, useAuth } from '@/lib/auth'
import { AppShell } from '@/components/layout/AppShell'
import { Button, Spinner } from '@/components/ui'
import { LoginPage } from '@/features/auth/LoginPage'
import { CommandCenter } from '@/features/dashboard/CommandCenter'

// Heavier routes are split so the first paint after sign-in stays fast.
const IdentitiesPage = lazy(() => import('@/features/identities/IdentitiesPage').then((m) => ({ default: m.IdentitiesPage })))
const InvestigatorWorkbench = lazy(() => import('@/features/investigate/InvestigatorWorkbench').then((m) => ({ default: m.InvestigatorWorkbench })))
const AlertsPage = lazy(() => import('@/features/alerts/AlertsPage').then((m) => ({ default: m.AlertsPage })))
const CasesPage = lazy(() => import('@/features/cases/CasesPage').then((m) => ({ default: m.CasesPage })))
const CaseDetailPage = lazy(() => import('@/features/cases/CaseDetailPage').then((m) => ({ default: m.CaseDetailPage })))
const DetectionsPage = lazy(() => import('@/features/detections/DetectionsPage').then((m) => ({ default: m.DetectionsPage })))
const ContextsPage = lazy(() => import('@/features/contexts/ContextsPage').then((m) => ({ default: m.ContextsPage })))
const CatalogPage = lazy(() => import('@/features/catalog/CatalogPage').then((m) => ({ default: m.CatalogPage })))
const SimulatorPage = lazy(() => import('@/features/simulator/SimulatorPage').then((m) => ({ default: m.SimulatorPage })))
const ExecutivePage = lazy(() => import('@/features/executive/ExecutivePage').then((m) => ({ default: m.ExecutivePage })))
const SettingsPage = lazy(() => import('@/features/settings/SettingsPage').then((m) => ({ default: m.SettingsPage })))
const ResponsePage = lazy(() => import('@/features/response/ResponsePage').then((m) => ({ default: m.ResponsePage })))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // Auth and client errors will not fix themselves; only retry transient faults.
        if (error instanceof ApiError && error.status < 500) return false
        return failureCount < 2
      },
    },
    mutations: { retry: false },
  },
})

/** Catches render-time faults so one broken panel cannot blank the whole console. */
class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error) {
    console.error('Console render error:', error)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="panel-raised max-w-md p-6 text-center">
          <h1 className="text-sm font-semibold">Something broke while rendering</h1>
          <p className="mt-2 text-xs leading-relaxed text-[--color-ink-muted]">
            {this.state.error.message}
          </p>
          <Button className="mt-4" variant="primary" onClick={() => window.location.reload()}>
            Reload the console
          </Button>
        </div>
      </div>
    )
  }
}

function FullPageSpinner() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Spinner className="size-6 text-[--color-accent]" />
    </div>
  )
}

function RouteSpinner() {
  return (
    <div className="flex h-64 items-center justify-center">
      <Spinner className="size-5 text-[--color-accent]" />
    </div>
  )
}

function RequireAuth() {
  const { user, loading } = useAuth()
  if (loading) return <FullPageSpinner />
  if (!user) return <Navigate to="/login" replace />
  return <AppShell />
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
      <p className="numeric text-5xl font-semibold text-[--color-ink-faint]">404</p>
      <p className="text-sm font-medium">That page does not exist</p>
      <p className="max-w-sm text-xs text-[--color-ink-muted]">
        Check the URL, or press <kbd className="rounded border border-[--color-border] px-1">⌘K</kbd> to
        jump somewhere.
      </p>
    </div>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route element={<RequireAuth />}>
                <Route
                  path="/"
                  element={
                    <Suspense fallback={<RouteSpinner />}>
                      <CommandCenter />
                    </Suspense>
                  }
                />
                {[
                  ['/identities', <IdentitiesPage key="i" />],
                  ['/investigate/:identityId', <InvestigatorWorkbench key="w" />],
                  ['/alerts', <AlertsPage key="a" />],
                  ['/cases', <CasesPage key="c" />],
                  ['/cases/:caseId', <CaseDetailPage key="cd" />],
                  ['/detections', <DetectionsPage key="d" />],
                  ['/contexts', <ContextsPage key="ctx" />],
                  ['/catalog', <CatalogPage key="cat" />],
                  ['/simulator', <SimulatorPage key="s" />],
                  ['/executive', <ExecutivePage key="e" />],
                  ['/response', <ResponsePage key="r" />],
                  ['/settings', <SettingsPage key="set" />],
                ].map(([path, element]) => (
                  <Route
                    key={path as string}
                    path={path as string}
                    element={<Suspense fallback={<RouteSpinner />}>{element as ReactNode}</Suspense>}
                  />
                ))}
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

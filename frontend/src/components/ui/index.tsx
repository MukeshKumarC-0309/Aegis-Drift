/** Primitive UI components shared across the console. */

import { forwardRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

/* ------------------------------------------------------------------ surfaces */

export function Panel({
  children,
  className,
  lit = false,
}: {
  children: ReactNode
  className?: string
  lit?: boolean
}) {
  return <div className={cn('panel', lit && 'panel-lit', className)}>{children}</div>
}

export function PanelHeader({
  title,
  subtitle,
  action,
  icon,
  className,
}: {
  title: ReactNode
  subtitle?: ReactNode
  action?: ReactNode
  icon?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex items-start justify-between gap-4 border-b border-[--color-border-subtle] px-5 py-4', className)}>
      <div className="flex min-w-0 items-start gap-3">
        {icon && <div className="mt-0.5 shrink-0 text-[--color-accent]">{icon}</div>}
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold tracking-tight text-[--color-ink]">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs leading-relaxed text-[--color-ink-muted]">{subtitle}</p>}
        </div>
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}

/* -------------------------------------------------------------------- button */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'subtle'
type ButtonSize = 'sm' | 'md' | 'lg'

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-cyan-500/15 text-cyan-200 border border-cyan-400/30 hover:bg-cyan-500/25 hover:border-cyan-400/50',
  secondary:
    'bg-[--color-surface-overlay] text-[--color-ink] border border-[--color-border] hover:border-[--color-border-strong] hover:bg-[--color-surface-raised]',
  ghost: 'text-[--color-ink-muted] hover:text-[--color-ink] hover:bg-white/5 border border-transparent',
  danger: 'bg-rose-500/15 text-rose-200 border border-rose-400/30 hover:bg-rose-500/25 hover:border-rose-400/50',
  subtle: 'bg-white/5 text-[--color-ink-muted] border border-transparent hover:bg-white/10 hover:text-[--color-ink]',
}

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-7 px-2.5 text-xs gap-1.5',
  md: 'h-9 px-3.5 text-sm gap-2',
  lg: 'h-11 px-5 text-sm gap-2',
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  icon?: ReactNode
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', loading, icon, className, children, disabled, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(
        'inline-flex items-center justify-center rounded-lg font-medium transition-all',
        'disabled:cursor-not-allowed disabled:opacity-45',
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner className="size-3.5" /> : icon}
      {children}
    </button>
  )
})

export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={cn('size-4 animate-spin', className)} viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
      <path
        d="M12 2a10 10 0 0 1 10 10"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        className="opacity-90"
      />
    </svg>
  )
}

/* --------------------------------------------------------------------- badge */

export function Badge({
  children,
  className,
  dot,
  title,
}: {
  children: ReactNode
  className?: string
  dot?: string
  title?: string
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap',
        'border-[--color-border] bg-white/5 text-[--color-ink-muted]',
        className,
      )}
    >
      {dot && <span className={cn('size-1.5 rounded-full', dot)} />}
      {children}
    </span>
  )
}

/* --------------------------------------------------------------------- forms */

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return (
      <input
        ref={ref}
        className={cn(
          'h-9 w-full rounded-lg border border-[--color-border] bg-[--color-surface] px-3 text-sm',
          'text-[--color-ink] placeholder:text-[--color-ink-faint]',
          'transition-colors focus:border-cyan-400/50 focus:outline-none',
          'disabled:cursor-not-allowed disabled:opacity-50',
          className,
        )}
        {...rest}
      />
    )
  },
)

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, children, ...rest }, ref) {
    return (
      <select
        ref={ref}
        className={cn(
          'h-9 w-full appearance-none rounded-lg border border-[--color-border] bg-[--color-surface] px-3 pr-8 text-sm',
          'text-[--color-ink] transition-colors focus:border-cyan-400/50 focus:outline-none',
          "bg-[url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='%2394a3b8'%3E%3Cpath d='M4.5 6.5L8 10l3.5-3.5z'/%3E%3C/svg%3E\")]",
          'bg-[length:16px] bg-[right_0.5rem_center] bg-no-repeat',
          className,
        )}
        {...rest}
      >
        {children}
      </select>
    )
  },
)

export function Field({
  label,
  hint,
  error,
  children,
  className,
}: {
  label: string
  hint?: string
  error?: string
  children: ReactNode
  className?: string
}) {
  return (
    <label className={cn('block', className)}>
      <span className="mb-1.5 block text-xs font-medium text-[--color-ink-muted]">{label}</span>
      {children}
      {error ? (
        <span className="mt-1 block text-xs text-rose-300">{error}</span>
      ) : (
        hint && <span className="mt-1 block text-xs text-[--color-ink-faint]">{hint}</span>
      )}
    </label>
  )
}

/* -------------------------------------------------------------------- states */

export function EmptyState({
  title,
  description,
  action,
  icon,
}: {
  title: string
  description?: string
  action?: ReactNode
  icon?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      {icon && <div className="text-[--color-ink-faint]">{icon}</div>}
      <div>
        <p className="text-sm font-medium text-[--color-ink]">{title}</p>
        {description && (
          <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-[--color-ink-muted]">{description}</p>
        )}
      </div>
      {action}
    </div>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-shimmer rounded-md', className)} />
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const message = error instanceof Error ? error.message : 'Something went wrong.'
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
      <div className="flex size-10 items-center justify-center rounded-full border border-rose-500/30 bg-rose-500/10">
        <svg className="size-5 text-rose-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
        </svg>
      </div>
      <div>
        <p className="text-sm font-medium text-[--color-ink]">Could not load this view</p>
        <p className="mt-1 max-w-md text-xs text-[--color-ink-muted]">{message}</p>
      </div>
      {retry && (
        <Button size="sm" onClick={retry}>
          Retry
        </Button>
      )}
    </div>
  )
}

/* --------------------------------------------------------------------- misc */

export function Progress({
  value,
  max = 100,
  color,
  className,
}: {
  value: number
  max?: number
  color?: string
  className?: string
}) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className={cn('h-1.5 w-full overflow-hidden rounded-full bg-white/8', className)}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${pct}%`, backgroundColor: color ?? 'var(--color-accent)' }}
      />
    </div>
  )
}

export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
  className,
}: {
  tabs: { id: T; label: string; count?: number }[]
  active: T
  onChange: (id: T) => void
  className?: string
}) {
  return (
    <div className={cn('flex gap-1 overflow-x-auto border-b border-[--color-border-subtle]', className)} role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={active === tab.id}
          onClick={() => onChange(tab.id)}
          className={cn(
            'relative whitespace-nowrap px-3.5 py-2.5 text-xs font-medium transition-colors',
            active === tab.id
              ? 'text-[--color-ink]'
              : 'text-[--color-ink-muted] hover:text-[--color-ink]',
          )}
        >
          {tab.label}
          {tab.count !== undefined && (
            <span className="ml-1.5 rounded px-1 py-0.5 text-[10px] text-[--color-ink-faint] tabular-nums">
              {tab.count}
            </span>
          )}
          {active === tab.id && (
            <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-[--color-accent]" />
          )}
        </button>
      ))}
    </div>
  )
}

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = 'max-w-lg',
}: {
  open: boolean
  onClose: () => void
  title: string
  description?: string
  children: ReactNode
  footer?: ReactNode
  width?: string
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 pt-[8vh]">
      <div
        className="fixed inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
        role="presentation"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn('panel-raised animate-slide-up relative w-full shadow-2xl', width)}
      >
        <div className="flex items-start justify-between gap-4 border-b border-[--color-border-subtle] px-5 py-4">
          <div>
            <h2 className="text-sm font-semibold text-[--color-ink]">{title}</h2>
            {description && <p className="mt-1 text-xs text-[--color-ink-muted]">{description}</p>}
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded p-1 text-[--color-ink-faint] transition-colors hover:bg-white/5 hover:text-[--color-ink]"
          >
            <svg className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="max-h-[65vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && (
          <div className="flex justify-end gap-2 border-t border-[--color-border-subtle] px-5 py-3">{footer}</div>
        )}
      </div>
    </div>
  )
}

export function Stat({
  label,
  value,
  sublabel,
  accent,
  className,
}: {
  label: string
  value: ReactNode
  sublabel?: ReactNode
  accent?: string
  className?: string
}) {
  return (
    <div className={cn('min-w-0', className)}>
      <p className="text-[11px] font-medium tracking-wide text-[--color-ink-faint] uppercase">{label}</p>
      <p className="numeric mt-1 text-2xl leading-none font-semibold" style={accent ? { color: accent } : undefined}>
        {value}
      </p>
      {sublabel && <p className="mt-1.5 truncate text-xs text-[--color-ink-muted]">{sublabel}</p>}
    </div>
  )
}

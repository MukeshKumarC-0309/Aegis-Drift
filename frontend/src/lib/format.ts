import { formatDistanceToNowStrict, format, parseISO } from 'date-fns'
import type { Severity, TransitionState } from '@/types/api'

/** Server timestamps are naive UTC; append Z so the browser converts correctly. */
function toDate(value: string | Date): Date {
  if (value instanceof Date) return value
  const normalised = /[Z+]|-\d{2}:\d{2}$/.test(value) ? value : `${value}Z`
  return parseISO(normalised)
}

export function relativeTime(value: string | Date | null | undefined): string {
  if (!value) return '—'
  try {
    return `${formatDistanceToNowStrict(toDate(value))} ago`
  } catch {
    return '—'
  }
}

export function absoluteTime(value: string | Date | null | undefined, pattern = 'dd MMM yyyy HH:mm'): string {
  if (!value) return '—'
  try {
    return format(toDate(value), pattern)
  } catch {
    return '—'
  }
}

export function shortTime(value: string | Date | null | undefined): string {
  return absoluteTime(value, 'dd MMM HH:mm')
}

export function compactNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(value)
}

export function fullNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  return new Intl.NumberFormat('en').format(value)
}

export function percent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined) return '—'
  return `${value.toFixed(digits)}%`
}

export function bytes(value: number | null | undefined): string {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

/** Human label for a snake_case or SCREAMING_CASE token. */
export function titleise(value: string | null | undefined): string {
  if (!value) return '—'
  return value
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export const SENSITIVITY_LABELS: Record<number, string> = {
  1: 'Public',
  2: 'Internal',
  3: 'Confidential',
  4: 'Restricted',
  5: 'Crown Jewel',
}

/* -------------------------------------------------------------- risk semantics
   Colour is load-bearing here: a state always renders in the same hue across
   every chart, badge and table so the estate can be scanned at a glance.        */

export const STATE_META: Record<
  TransitionState,
  { label: string; color: string; bg: string; border: string; text: string; dot: string }
> = {
  STABLE: {
    label: 'Stable',
    color: 'var(--color-stable)',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-300',
    dot: 'bg-emerald-400',
  },
  EARLY_DRIFT: {
    label: 'Early drift',
    color: 'var(--color-drift)',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-300',
    dot: 'bg-amber-400',
  },
  ESCALATING: {
    label: 'Escalating',
    color: 'var(--color-escalating)',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    text: 'text-orange-300',
    dot: 'bg-orange-400',
  },
  CRITICAL_TRANSITION: {
    label: 'Critical',
    color: 'var(--color-critical)',
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/40',
    text: 'text-rose-300',
    dot: 'bg-rose-400',
  },
}

export const SEVERITY_META: Record<Severity, { label: string; text: string; bg: string; border: string }> = {
  INFO: { label: 'Info', text: 'text-slate-300', bg: 'bg-slate-500/10', border: 'border-slate-500/30' },
  LOW: { label: 'Low', text: 'text-emerald-300', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
  MEDIUM: { label: 'Medium', text: 'text-amber-300', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
  HIGH: { label: 'High', text: 'text-orange-300', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  CRITICAL: { label: 'Critical', text: 'text-rose-300', bg: 'bg-rose-500/10', border: 'border-rose-500/40' },
}

export function riskColor(score: number): string {
  if (score >= 75) return 'var(--color-critical)'
  if (score >= 50) return 'var(--color-escalating)'
  if (score >= 28) return 'var(--color-drift)'
  return 'var(--color-stable)'
}

export function riskTextClass(score: number): string {
  if (score >= 75) return 'text-rose-300'
  if (score >= 50) return 'text-orange-300'
  if (score >= 28) return 'text-amber-300'
  return 'text-emerald-300'
}

export const VECTOR_LABELS: Record<string, string> = {
  temporal: 'Circadian',
  resource: 'Resource',
  privilege: 'Privilege',
  peer_divergence: 'Peer divergence',
  geovelocity: 'Geo-velocity',
  volume: 'Data volume',
  device: 'Device',
  intel: 'Threat intel',
}

/** Chart palette for categorical series — colour-blind safe and distinct on dark. */
export const SERIES_COLORS = [
  '#22d3ee',
  '#818cf8',
  '#f472b6',
  '#fbbf24',
  '#34d399',
  '#fb923c',
  '#a78bfa',
  '#60a5fa',
]

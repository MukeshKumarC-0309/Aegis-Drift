/**
 * Chart components.
 *
 * Every chart shares one colour language (see `lib/format`): a hue means a risk
 * state, never a series index, so a reader never has to re-learn the legend.
 */

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  ComposedChart,
  Pie,
  PieChart,
} from 'recharts'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { riskColor, shortTime, STATE_META, VECTOR_LABELS } from '@/lib/format'
import type { TimelinePoint, TransitionState } from '@/types/api'

const AXIS = {
  stroke: '#3b4a61',
  tick: { fill: '#7c8da5', fontSize: 11 },
  tickLine: false,
  axisLine: false,
}

const GRID = { stroke: '#1b2430', strokeDasharray: '3 3' }

function TooltipShell({ children }: { children: ReactNode }) {
  return (
    <div className="panel-raised px-3 py-2 text-xs shadow-xl">
      {children}
    </div>
  )
}

/* ------------------------------------------------------- risk trajectory */

interface TimelineProps {
  points: TimelinePoint[]
  thresholds?: { drift: number; escalating: number; critical: number }
  height?: number
  showRaw?: boolean
}

/**
 * The signature chart: cumulative risk over time against the per-event scores
 * that produced it, with the raw (undamped) trace overlaid so an analyst can see
 * exactly how much context damping removed.
 */
export function RiskTrajectory({
  points,
  thresholds = { drift: 28, escalating: 50, critical: 75 },
  height = 280,
  showRaw = true,
}: TimelineProps) {
  const data = points.map((p) => ({
    ts: p.timestamp,
    label: shortTime(p.timestamp),
    risk: p.cumulative_risk,
    raw: p.raw_cumulative_risk,
    event: p.event_score,
    rawEvent: p.raw_event_score,
    resource: p.resource,
    action: p.action,
    damped: p.is_damped,
    antiTamper: p.anti_tamper,
    state: p.state,
  }))

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ComposedChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid {...GRID} vertical={false} />
        <XAxis dataKey="label" {...AXIS} minTickGap={48} />
        <YAxis domain={[0, 100]} {...AXIS} width={44} />

        <ReferenceLine y={thresholds.drift} stroke="#fbbf24" strokeDasharray="4 4" strokeOpacity={0.5} />
        <ReferenceLine y={thresholds.escalating} stroke="#fb923c" strokeDasharray="4 4" strokeOpacity={0.5} />
        <ReferenceLine y={thresholds.critical} stroke="#f43f5e" strokeDasharray="4 4" strokeOpacity={0.6} />

        <Tooltip
          cursor={{ stroke: '#33415a' }}
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const d = payload[0].payload as (typeof data)[number]
            return (
              <TooltipShell>
                <p className="mb-1 font-medium text-[--color-ink]">{d.label}</p>
                <p className="text-[--color-ink-muted]">
                  <span className="font-mono">{d.action}</span> on{' '}
                  <span className="font-mono">{d.resource}</span>
                </p>
                <div className="mt-1.5 space-y-0.5">
                  <p>
                    Cumulative risk: <span className="numeric font-semibold text-cyan-300">{d.risk.toFixed(1)}</span>
                  </p>
                  {showRaw && d.raw !== d.risk && (
                    <p className="text-[--color-ink-muted]">
                      Undamped: <span className="numeric">{d.raw.toFixed(1)}</span>
                    </p>
                  )}
                  <p className="text-[--color-ink-muted]">
                    This event: <span className="numeric">{d.event.toFixed(1)}</span>
                  </p>
                </div>
                {d.damped && <p className="mt-1 text-indigo-300">Context damped</p>}
                {d.antiTamper && <p className="mt-1 font-medium text-rose-300">Anti-tamper override</p>}
              </TooltipShell>
            )
          }}
        />

        <Bar dataKey="event" barSize={5} radius={[2, 2, 0, 0]} opacity={0.5}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.antiTamper ? '#f43f5e' : d.damped ? '#818cf8' : riskColor(d.event)} />
          ))}
        </Bar>

        {showRaw && (
          <Line
            type="monotone"
            dataKey="raw"
            stroke="#64748b"
            strokeWidth={1.5}
            strokeDasharray="4 3"
            dot={false}
            name="Undamped"
          />
        )}
        <Area
          type="monotone"
          dataKey="risk"
          stroke="#22d3ee"
          strokeWidth={2}
          fill="url(#riskFill)"
          dot={false}
          name="Cumulative risk"
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}

/* ------------------------------------------------------------ vector radar */

export function VectorRadar({
  scores,
  height = 260,
  comparison,
}: {
  scores: Record<string, number>
  height?: number
  comparison?: Record<string, number>
}) {
  const data = Object.entries(scores).map(([vector, value]) => ({
    vector: VECTOR_LABELS[vector] ?? vector,
    value: Number(value.toFixed(1)),
    baseline: comparison?.[vector] ?? 0,
  }))

  if (data.every((d) => d.value === 0)) {
    return (
      <div
        className="flex items-center justify-center text-xs text-[--color-ink-muted]"
        style={{ height }}
      >
        No vector activity in this window.
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadarChart data={data} outerRadius="72%">
        <PolarGrid stroke="#243044" />
        <PolarAngleAxis dataKey="vector" tick={{ fill: '#94a3b8', fontSize: 10 }} />
        <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#5b6b82', fontSize: 9 }} axisLine={false} />
        {comparison && (
          <Radar name="Cohort" dataKey="baseline" stroke="#64748b" fill="#64748b" fillOpacity={0.12} />
        )}
        <Radar name="Identity" dataKey="value" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.28} />
        <Tooltip
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            return (
              <TooltipShell>
                <p className="font-medium">{payload[0].payload.vector}</p>
                {payload.map((p) => (
                  <p key={p.name} className="text-[--color-ink-muted]">
                    {p.name}: <span className="numeric">{Number(p.value).toFixed(1)}</span>
                  </p>
                ))}
              </TooltipShell>
            )
          }}
        />
        {comparison && <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />}
      </RadarChart>
    </ResponsiveContainer>
  )
}

/* -------------------------------------------------------- state distribution */

export function StateDistribution({
  distribution,
  height = 200,
}: {
  distribution: { key: string; label: string; count: number; percentage: number }[]
  height?: number
}) {
  const data = distribution.filter((d) => d.count > 0)
  if (!data.length) {
    return <div className="flex items-center justify-center text-xs text-[--color-ink-muted]" style={{ height }}>No data</div>
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          dataKey="count"
          nameKey="label"
          innerRadius="58%"
          outerRadius="82%"
          paddingAngle={2}
          stroke="none"
        >
          {data.map((d) => (
            <Cell key={d.key} fill={STATE_META[d.key as TransitionState]?.color ?? '#64748b'} />
          ))}
        </Pie>
        <Tooltip
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const d = payload[0].payload as (typeof data)[number]
            return (
              <TooltipShell>
                <p className="font-medium">{d.label}</p>
                <p className="text-[--color-ink-muted]">
                  <span className="numeric">{d.count}</span> identities · {d.percentage}%
                </p>
              </TooltipShell>
            )
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

/* ------------------------------------------------------------- volume trend */

export function VolumeTrend({
  points,
  height = 160,
  color = '#22d3ee',
  label = 'Events',
}: {
  points: { timestamp: string; value: number; label: string | null }[]
  height?: number
  color?: string
  label?: string
}) {
  if (!points.length) {
    return (
      <div className="flex items-center justify-center text-xs text-[--color-ink-muted]" style={{ height }}>
        No history yet — trends appear once snapshots accumulate.
      </div>
    )
  }
  const data = points.map((p) => ({ ...p, short: shortTime(p.timestamp) }))

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 6, right: 8, left: -22, bottom: 0 }}>
        <defs>
          <linearGradient id={`vt-${label}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.3} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid {...GRID} vertical={false} />
        <XAxis dataKey="short" {...AXIS} minTickGap={40} />
        <YAxis {...AXIS} width={42} />
        <Tooltip
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const d = payload[0].payload as (typeof data)[number]
            return (
              <TooltipShell>
                <p className="font-medium">{d.short}</p>
                <p className="text-[--color-ink-muted]">
                  {label}: <span className="numeric">{d.value.toLocaleString()}</span>
                </p>
                {d.label && <p className="text-[--color-ink-faint]">{d.label}</p>}
              </TooltipShell>
            )
          }}
        />
        <Area type="monotone" dataKey="value" stroke={color} strokeWidth={2} fill={`url(#vt-${label})`} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

/* ----------------------------------------------------------- department bars */

export function DepartmentRisk({
  rows,
  height = 240,
}: {
  rows: { department: string; mean_risk: number; max_risk: number; identity_count: number; at_risk_count: number }[]
  height?: number
}) {
  const data = [...rows].sort((a, b) => b.mean_risk - a.mean_risk)
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 4, bottom: 4 }}>
        <CartesianGrid {...GRID} horizontal={false} />
        <XAxis type="number" domain={[0, 100]} {...AXIS} />
        <YAxis type="category" dataKey="department" {...AXIS} width={104} />
        <Tooltip
          cursor={{ fill: 'rgba(255,255,255,0.03)' }}
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const d = payload[0].payload as (typeof data)[number]
            return (
              <TooltipShell>
                <p className="font-medium">{d.department}</p>
                <p className="text-[--color-ink-muted]">
                  Mean risk <span className="numeric">{d.mean_risk}</span> · peak{' '}
                  <span className="numeric">{d.max_risk}</span>
                </p>
                <p className="text-[--color-ink-muted]">
                  {d.at_risk_count} of {d.identity_count} identities drifting
                </p>
              </TooltipShell>
            )
          }}
        />
        <Bar dataKey="mean_risk" radius={[0, 4, 4, 0]} barSize={14}>
          {data.map((d) => (
            <Cell key={d.department} fill={riskColor(d.mean_risk)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

/* ------------------------------------------------------------ vector heatmap */

export function VectorHeatmap({ scores }: { scores: Record<string, number> }) {
  const entries = Object.entries(scores).sort((a, b) => b[1] - a[1])
  if (!entries.length) {
    return <p className="px-5 py-8 text-center text-xs text-[--color-ink-muted]">No drifting identities.</p>
  }
  const max = Math.max(...entries.map(([, v]) => v), 1)

  return (
    <div className="space-y-2.5 px-5 py-4">
      {entries.map(([vector, value]) => (
        <div key={vector}>
          <div className="mb-1 flex items-baseline justify-between text-xs">
            <span className="text-[--color-ink-muted]">{VECTOR_LABELS[vector] ?? vector}</span>
            <span className="numeric text-[--color-ink]">{value.toFixed(1)}</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{ width: `${(value / max) * 100}%`, backgroundColor: riskColor(value) }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

/* --------------------------------------------------------------- sparkline */

export function Sparkline({
  values,
  color = '#22d3ee',
  className,
}: {
  values: number[]
  color?: string
  className?: string
}) {
  if (values.length < 2) return <div className={cn('h-6', className)} />
  const max = Math.max(...values, 1)
  const min = Math.min(...values, 0)
  const range = max - min || 1
  const points = values
    .map((v, i) => `${(i / (values.length - 1)) * 100},${100 - ((v - min) / range) * 100}`)
    .join(' ')

  return (
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" className={cn('h-6 w-full', className)} aria-hidden>
      <polyline points={points} fill="none" stroke={color} strokeWidth="3" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

/* ---------------------------------------------------------- circadian clock */

/**
 * Hour-of-day histogram rendered as a 24-segment ring. A radial form is the
 * honest one here: the data is cyclical, and 23:00 really is adjacent to 00:00.
 */
export function CircadianRing({
  distribution,
  observedHours = [],
  size = 180,
}: {
  distribution: Record<string, number>
  observedHours?: number[]
  size?: number
}) {
  const values = Array.from({ length: 24 }, (_, h) => distribution[String(h)] ?? distribution[h] ?? 0)
  const max = Math.max(...values, 0.001)
  const center = size / 2
  const inner = size * 0.24
  const outer = size * 0.44
  const observed = new Set(observedHours)

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="mx-auto">
      <circle cx={center} cy={center} r={outer} fill="none" stroke="#1b2430" strokeWidth="1" />
      <circle cx={center} cy={center} r={inner} fill="none" stroke="#1b2430" strokeWidth="1" />

      {values.map((value, hour) => {
        const angle = (hour / 24) * Math.PI * 2 - Math.PI / 2
        const next = ((hour + 1) / 24) * Math.PI * 2 - Math.PI / 2
        const mid = (angle + next) / 2
        const length = inner + (value / max) * (outer - inner)
        const isObserved = observed.has(hour)

        return (
          <g key={hour}>
            <line
              x1={center + Math.cos(mid) * inner}
              y1={center + Math.sin(mid) * inner}
              x2={center + Math.cos(mid) * length}
              y2={center + Math.sin(mid) * length}
              stroke={isObserved ? '#f43f5e' : '#22d3ee'}
              strokeWidth={size * 0.042}
              strokeLinecap="round"
              opacity={isObserved ? 0.95 : 0.65}
            >
              <title>{`${String(hour).padStart(2, '0')}:00 — ${(value * 100).toFixed(1)}% of baseline activity${isObserved ? ' · anomalous activity observed' : ''}`}</title>
            </line>
            {hour % 6 === 0 && (
              <text
                x={center + Math.cos(mid) * (outer + size * 0.075)}
                y={center + Math.sin(mid) * (outer + size * 0.075)}
                fill="#5b6b82"
                fontSize={size * 0.06}
                textAnchor="middle"
                dominantBaseline="middle"
              >
                {String(hour).padStart(2, '0')}
              </text>
            )}
          </g>
        )
      })}

      <text x={center} y={center - 5} fill="#94a3b8" fontSize={size * 0.062} textAnchor="middle">
        Baseline
      </text>
      <text x={center} y={center + 9} fill="#5b6b82" fontSize={size * 0.055} textAnchor="middle">
        by hour
      </text>
    </svg>
  )
}

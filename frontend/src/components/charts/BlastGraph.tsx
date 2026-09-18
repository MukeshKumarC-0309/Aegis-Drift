import { useMemo, useState } from 'react'
import type { BlastRadius } from '@/types/api'
import { compactNumber } from '@/lib/format'
import { cn } from '@/lib/utils'

/**
 * Topological blast-radius graph.
 *
 * A deterministic radial layout rather than a force simulation: the same estate
 * always renders identically, so an analyst comparing two investigations is
 * comparing the data and not the physics. Assets orbit their category, which
 * orbits the identity.
 */

const TIER_COLOR: Record<number, string> = {
  1: '#475569',
  2: '#0891b2',
  3: '#fbbf24',
  4: '#fb923c',
  5: '#f43f5e',
}

interface Placed {
  id: string
  x: number
  y: number
  r: number
  label: string
  sublabel: string
  type: string
  sensitivity: number
  records?: number
}

export function BlastGraph({ blast, height = 420 }: { blast: BlastRadius; height?: number }) {
  const [hovered, setHovered] = useState<string | null>(null)

  const { nodes, edges, width } = useMemo(() => {
    const W = 760
    const H = height
    const cx = W / 2
    const cy = H / 2

    const categories = blast.graph.nodes.filter((n) => n.type === 'category')
    const assets = blast.graph.nodes.filter((n) => n.type === 'asset' || n.type === 'crown_jewel')
    const identity = blast.graph.nodes.find((n) => n.type === 'identity')

    const placed = new Map<string, Placed>()

    if (identity) {
      placed.set(identity.id, {
        id: identity.id,
        x: cx,
        y: cy,
        r: 22,
        label: identity.label,
        sublabel: identity.sublabel,
        type: 'identity',
        sensitivity: 0,
      })
    }

    // Category ring.
    const catRadius = Math.min(W, H) * 0.17
    categories.forEach((cat, i) => {
      const angle = (i / Math.max(categories.length, 1)) * Math.PI * 2 - Math.PI / 2
      placed.set(cat.id, {
        id: cat.id,
        x: cx + Math.cos(angle) * catRadius,
        y: cy + Math.sin(angle) * catRadius,
        r: 9,
        label: cat.label,
        sublabel: cat.sublabel,
        type: 'category',
        sensitivity: 0,
      })
    })

    // Assets fan out from their own category, staying inside the viewport.
    const byCategory = new Map<string, typeof assets>()
    for (const edge of blast.graph.edges) {
      if (edge.kind !== 'accesses') continue
      const list = byCategory.get(edge.source) ?? []
      const asset = assets.find((a) => a.id === edge.target)
      if (asset) list.push(asset)
      byCategory.set(edge.source, list)
    }

    const assetRadius = Math.min(W, H) * 0.34
    for (const [catId, list] of byCategory) {
      const cat = placed.get(catId)
      if (!cat) continue
      const baseAngle = Math.atan2(cat.y - cy, cat.x - cx)
      const spread = Math.min(Math.PI * 0.62, 0.26 * list.length)

      list.forEach((asset, i) => {
        const offset = list.length === 1 ? 0 : (i / (list.length - 1) - 0.5) * spread
        const angle = baseAngle + offset
        // Alternate the orbit so dense categories do not collide.
        const radius = assetRadius + (i % 3) * 26
        placed.set(asset.id, {
          id: asset.id,
          x: cx + Math.cos(angle) * radius,
          y: cy + Math.sin(angle) * radius,
          r: 5 + asset.sensitivity * 1.9,
          label: asset.label,
          sublabel: asset.sublabel,
          type: asset.type,
          sensitivity: asset.sensitivity,
          records: asset.records,
        })
      })
    }

    return {
      nodes: [...placed.values()],
      edges: blast.graph.edges
        .map((e) => ({ ...e, from: placed.get(e.source), to: placed.get(e.target) }))
        .filter((e) => e.from && e.to),
      width: W,
    }
  }, [blast, height])

  const connected = useMemo(() => {
    if (!hovered) return null
    const set = new Set<string>([hovered])
    for (const e of edges) {
      if (e.source === hovered) set.add(e.target)
      if (e.target === hovered) set.add(e.source)
    }
    return set
  }, [hovered, edges])

  const dim = (id: string) => (connected && !connected.has(id) ? 0.18 : 1)

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        style={{ maxHeight: height }}
        role="img"
        aria-label={`Blast radius graph: ${blast.assets_touched} assets reached by ${blast.username}`}
      >
        <defs>
          <radialGradient id="identityGlow">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
          </radialGradient>
        </defs>

        {edges.map((edge, i) => (
          <line
            key={i}
            x1={edge.from!.x}
            y1={edge.from!.y}
            x2={edge.to!.x}
            y2={edge.to!.y}
            stroke={edge.kind === 'groups' ? '#243044' : TIER_COLOR[edge.to!.sensitivity] ?? '#243044'}
            strokeWidth={edge.kind === 'groups' ? 1.2 : Math.min(3, 0.6 + Math.log1p(edge.weight) * 0.5)}
            strokeOpacity={0.35 * dim(edge.source) * dim(edge.target)}
          />
        ))}

        {nodes.map((node) => {
          const isIdentity = node.type === 'identity'
          const isCrown = node.type === 'crown_jewel'
          const color = isIdentity ? '#22d3ee' : TIER_COLOR[node.sensitivity] ?? '#475569'

          return (
            <g
              key={node.id}
              opacity={dim(node.id)}
              onMouseEnter={() => setHovered(node.id)}
              onMouseLeave={() => setHovered(null)}
              className="cursor-pointer transition-opacity"
            >
              {isIdentity && <circle cx={node.x} cy={node.y} r={54} fill="url(#identityGlow)" />}
              {isCrown && (
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={node.r + 5}
                  fill="none"
                  stroke="#f43f5e"
                  strokeWidth={1}
                  strokeOpacity={0.5}
                  strokeDasharray="3 3"
                />
              )}
              <circle
                cx={node.x}
                cy={node.y}
                r={node.r}
                fill={isIdentity ? '#0a0e14' : color}
                fillOpacity={isIdentity ? 1 : 0.85}
                stroke={color}
                strokeWidth={isIdentity ? 2 : 1}
              />
              {isIdentity && (
                <text
                  x={node.x}
                  y={node.y + 4}
                  textAnchor="middle"
                  fill="#22d3ee"
                  fontSize={11}
                  fontWeight={600}
                >
                  {node.label.slice(0, 2).toUpperCase()}
                </text>
              )}
              {(isIdentity || node.type === 'category' || hovered === node.id || node.sensitivity >= 4) && (
                <text
                  x={node.x}
                  y={node.y + node.r + 13}
                  textAnchor="middle"
                  fill={hovered === node.id ? '#e8edf5' : '#7c8da5'}
                  fontSize={hovered === node.id ? 11 : 9.5}
                  className="pointer-events-none select-none"
                >
                  {node.label.length > 26 ? `${node.label.slice(0, 24)}…` : node.label}
                </text>
              )}
              <title>
                {`${node.label}\n${node.sublabel}${node.records ? `\n~${node.records.toLocaleString()} records` : ''}`}
              </title>
            </g>
          )
        })}
      </svg>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-[--color-border-subtle] px-5 py-2.5 text-[11px] text-[--color-ink-muted]">
        {[1, 2, 3, 4, 5].map((tier) => (
          <span key={tier} className="inline-flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ backgroundColor: TIER_COLOR[tier] }} />
            Tier {tier}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="size-2 rounded-full border border-dashed border-rose-400" />
          Crown jewel
        </span>
        <span className="ml-auto">
          {blast.assets_touched} assets · {compactNumber(blast.records_at_risk)} records ·{' '}
          <span className={cn(blast.blast_radius_score >= 60 ? 'text-rose-300' : 'text-[--color-ink]')}>
            {blast.impact_level}
          </span>
        </span>
      </div>
    </div>
  )
}

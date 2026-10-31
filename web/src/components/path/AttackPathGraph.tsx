import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D, { type ForceGraphMethods } from 'react-force-graph-2d'
import { Download, Maximize2, Pause, Play, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useElementWidth } from '@/hooks/useElementWidth'
import { saveBlob } from '@/lib/download'
import { cn } from '@/lib/utils'
import {
  CARD_FONT,
  DEFAULT_REACH_LIMIT,
  NODE_KIND_COLOR,
  NODE_KIND_LABEL,
  REACH_COLOR,
  graphHeight,
  layoutPathGraph,
  linkVisible,
  type PathLink,
  type PathNode,
} from '@/lib/pathGraph'
import { tacticColor } from '@/lib/killchain'
import type { GraphEdge, GraphNode, NodeKind, Step } from '@/types/incident'

const PLAY_INTERVAL_MS = 1400
const MAX_ZOOM_AFTER_FIT = 1.6
const FONT = 'Inter, system-ui, sans-serif'
const BACKGROUND = '#f8fafc'
/** Room for labels when fitting, in graph units (labels are ~11 px at zoom 1). */
const REACH_LABEL_WIDTH = 120
const LABEL_HALF_WIDTH = 70
const LABEL_HEIGHT = 32

/** react-force-graph replaces link ends with the node objects once it has laid them out. */
type Placed = PathNode & { x?: number; y?: number }
type DrawnLink = Omit<PathLink, 'source' | 'target'> & { source: string | Placed; target: string | Placed }
type ReachMode = 'top' | 'all' | 'off'

function end(v: string | Placed): Placed | null {
  return typeof v === 'object' && v !== null ? v : null
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath()
  ctx.moveTo(x + r, y)
  ctx.arcTo(x + w, y, x + w, y + h, r)
  ctx.arcTo(x + w, y + h, x, y + h, r)
  ctx.arcTo(x, y + h, x, y, r)
  ctx.arcTo(x, y, x + w, y, r)
  ctx.closePath()
}

interface Props {
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
  chain: Step[]
  /** Download name for the PNG, e.g. "incident-1-attack-path". */
  fileName: string
  onNodeClick?: (nodeId: string) => void
  onStepClick?: (step: number) => void
}

/**
 * The attack path (FR-5): hosts, accounts and domains left to right in the
 * order the attacker reached them. Steps between the same two nodes are one
 * bundle with a card listing them; reach-next is dashed and cut to the top
 * three per node unless asked for all. Play highlights steps 1..N in order.
 */
export function AttackPathGraph({ graph, chain, fileName, onNodeClick, onStepClick }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const fgRef = useRef<ForceGraphMethods<Placed, DrawnLink> | undefined>(undefined)
  const width = useElementWidth(wrapRef)
  const [upTo, setUpTo] = useState<number | null>(null)
  const [playing, setPlaying] = useState(false)
  const [reachMode, setReachMode] = useState<ReachMode>('top')
  const [showSupporting, setShowSupporting] = useState(false)

  const reachLimit = reachMode === 'all' ? null : reachMode === 'off' ? 0 : DEFAULT_REACH_LIMIT
  const layout = useMemo(() => layoutPathGraph(graph, chain, { reachLimit, showSupporting }),
    [graph, chain, reachLimit, showSupporting])
  const full = useMemo(() => layoutPathGraph(graph, chain, { reachLimit: null, showSupporting: true }), [graph, chain])
  const height = graphHeight(layout)
  // Fresh objects for the library, which mutates them.
  const data = useMemo(
    // x/y as well as fx/fy: the simulation never ticks (cooldownTicks 0), so nodes must start where they belong
    () => ({ nodes: layout.nodes.map((n) => ({ ...n, x: n.fx, y: n.fy })) as Placed[], links: layout.links.map((l) => ({ ...l })) as DrawnLink[] }),
    [layout]
  )
  const lastStep = layout.steps[layout.steps.length - 1] ?? 0
  const current = upTo != null ? chain.find((s) => s.n === upTo) : undefined
  const reachTotal = full.nodes.filter((n) => n.reach).length
  const supportingTotal = full.links.filter((l) => l.supporting).length

  /**
   * Fit the whole drawing, labels included: reach-next labels sit to the right
   * of their nodes and other labels below, which force-graph's own zoomToFit
   * (node circles only) would clip. Small graphs are not blown up past MAX_ZOOM_AFTER_FIT.
   */
  const fit = useCallback(() => {
    const fg = fgRef.current
    const nodes = data.nodes
    if (!fg || nodes.length === 0 || !width) return
    let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity
    for (const n of nodes) {
      const x = n.x ?? n.fx
      const y = n.y ?? n.fy
      x0 = Math.min(x0, x - n.radius - (n.reach ? 0 : LABEL_HALF_WIDTH))
      x1 = Math.max(x1, x + n.radius + (n.reach ? REACH_LABEL_WIDTH : LABEL_HALF_WIDTH))
      y0 = Math.min(y0, y - n.radius - 8)
      y1 = Math.max(y1, y + n.radius + LABEL_HEIGHT)
    }
    const pad = 24
    const k = Math.min(MAX_ZOOM_AFTER_FIT, (width - pad * 2) / (x1 - x0), (height - pad * 2) / (y1 - y0))
    fg.centerAt((x0 + x1) / 2, (y0 + y1) / 2, 300)
    fg.zoom(k, 300)
  }, [data, width, height])
  useEffect(() => {
    const t = setTimeout(fit, 150)
    return () => clearTimeout(t)
  }, [fit])

  useEffect(() => {
    if (!playing) return
    const t = setInterval(() => {
      setUpTo((prev) => {
        const next = prev == null ? layout.steps[0] : layout.steps[layout.steps.indexOf(prev) + 1]
        if (next == null) {
          setPlaying(false)
          return prev
        }
        return next
      })
    }, PLAY_INTERVAL_MS)
    return () => clearInterval(t)
  }, [playing, layout.steps])

  const togglePlay = () => {
    if (playing) return setPlaying(false)
    if (upTo == null || upTo === lastStep) setUpTo(layout.steps[0] ?? null)
    setPlaying(true)
  }
  const reset = () => {
    setPlaying(false)
    setUpTo(null)
  }

  const exportPng = () => {
    const canvas = wrapRef.current?.querySelector('canvas')
    canvas?.toBlob((blob) => blob && saveBlob(blob, `${fileName}.png`), 'image/png')
  }

  const kinds = [...new Set(layout.nodes.filter((n) => !n.reach).map((n) => n.kind))] as NodeKind[]
  const hasReach = { observed: layout.nodes.some((n) => n.reach === 'observed'), inferred: layout.nodes.some((n) => n.reach === 'inferred') }

  const drawNode = useCallback(
    (node: Placed, ctx: CanvasRenderingContext2D, scale: number) => {
      const x = node.x ?? 0
      const y = node.y ?? 0
      const lit = upTo == null || node.steps.some((s) => s <= upTo) || (!!node.reach && upTo === lastStep)
      ctx.globalAlpha = lit ? 1 : 0.25
      ctx.beginPath()
      ctx.arc(x, y, node.radius, 0, 2 * Math.PI)
      if (node.reach) {
        ctx.fillStyle = '#ffffff'
        ctx.fill()
        ctx.setLineDash([3, 2])
        ctx.lineWidth = 1.6
        ctx.strokeStyle = node.color
        ctx.stroke()
        ctx.setLineDash([])
      } else {
        ctx.fillStyle = node.color
        ctx.fill()
        ctx.lineWidth = 2
        ctx.strokeStyle = '#ffffff'
        ctx.stroke()
      }
      const size = Math.max(11 / scale, 3.5)
      if (node.more) {
        ctx.font = `700 ${size * 0.85}px ${FONT}`
        ctx.fillStyle = '#475569'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(`+${node.more.count}`, x, y)
      }
      // labels: to the right of reach nodes (they stack in a column), under the others
      const right = !!node.reach
      const tx = right ? x + node.radius + 6 / scale : x
      const ty = right ? y - size * 0.55 : y + node.radius + 4 / scale
      ctx.textAlign = right ? 'left' : 'center'
      ctx.textBaseline = right ? 'middle' : 'top'
      // a halo in the background colour keeps labels readable where edges cross them
      ctx.lineJoin = 'round'
      ctx.lineWidth = 3 / scale
      ctx.strokeStyle = BACKGROUND
      const text = (s: string, ax: number, ay: number) => {
        ctx.strokeText(s, ax, ay)
        ctx.fillText(s, ax, ay)
      }
      ctx.font = `${node.reach ? 500 : 650} ${size}px ${FONT}`
      ctx.fillStyle = '#0f172a'
      const main = node.more ? `${node.more.count} more reachable` : node.label
      text(main, tx, ty)
      ctx.font = `${size * 0.82}px ${FONT}`
      ctx.fillStyle = '#64748b'
      const sub = node.more ? 'click to show all' : node.reach ? `reach next · ${node.reach}` : NODE_KIND_LABEL[node.kind] ?? node.kind
      text(sub, tx, right ? ty + size * 1.1 : ty + size * 1.15)
      ctx.globalAlpha = 1
    },
    [upTo, lastStep]
  )

  /** One card per bundle of steps between two nodes: a numbered, colour-coded line per step. */
  const drawLinkLabel = useCallback(
    (link: DrawnLink, ctx: CanvasRenderingContext2D, scale: number) => {
      if (!link.card) return
      const s = end(link.source)
      const t = end(link.target)
      if (!s || !t || s.x == null || s.y == null || t.x == null || t.y == null) return
      const lines = link.card
      const at = link.cardAt ?? 0.5
      const p = { x: s.x + (t.x - s.x) * at, y: s.y + (t.y - s.y) * at }
      // 10.5 px on screen, but never larger than the room the layout left (CARD_FONT graph units)
      // unless that would go below 7 px when zoomed far out
      const size = Math.max(Math.min(CARD_FONT, 10.5 / scale), 7 / scale)
      const lineH = size * 1.55
      const badge = size * 0.78
      const pad = size * 0.6
      ctx.font = `600 ${size}px ${FONT}`
      const textW = Math.max(...lines.map((l) => ctx.measureText(l.text + (l.supporting ? '  anomaly' : '')).width))
      const w = pad * 2 + badge * 2 + size * 0.5 + textW
      const h = pad * 2 + lineH * lines.length - (lineH - size)
      const x0 = p.x - w / 2
      const y0 = p.y - h / 2
      ctx.save()
      ctx.shadowColor = 'rgba(15,23,42,0.12)'
      ctx.shadowBlur = 6 / scale
      roundRect(ctx, x0, y0, w, h, size * 0.5)
      ctx.fillStyle = 'rgba(255,255,255,0.96)'
      ctx.fill()
      ctx.restore()
      ctx.lineWidth = 1 / scale
      ctx.strokeStyle = '#e2e8f0'
      roundRect(ctx, x0, y0, w, h, size * 0.5)
      ctx.stroke()
      lines.forEach((l, i) => {
        const cy = y0 + pad + size / 2 + i * lineH
        const on = upTo == null || (l.step != null && l.step <= upTo)
        const now = upTo != null && l.step === upTo
        ctx.globalAlpha = on ? 1 : 0.3
        const bx = x0 + pad + badge
        ctx.beginPath()
        ctx.arc(bx, cy, badge, 0, 2 * Math.PI)
        if (l.supporting) {
          ctx.fillStyle = '#ffffff'
          ctx.fill()
          ctx.lineWidth = 1.2 / scale
          ctx.strokeStyle = l.color
          ctx.stroke()
        } else {
          ctx.fillStyle = l.color
          ctx.fill()
        }
        ctx.font = `700 ${size * 0.78}px ${FONT}`
        ctx.fillStyle = l.supporting ? l.color : '#ffffff'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(String(l.step ?? ''), bx, cy + size * 0.03)
        ctx.font = `${now ? 750 : l.supporting ? 400 : 550} ${size}px ${FONT}`
        ctx.textAlign = 'left'
        ctx.fillStyle = l.supporting ? '#64748b' : '#0f172a'
        const tx = bx + badge + size * 0.5
        ctx.fillText(l.text, tx, cy)
        if (l.supporting) {
          const tw = ctx.measureText(l.text).width
          ctx.font = `italic ${size * 0.85}px ${FONT}`
          ctx.fillStyle = '#8b5cf6'
          ctx.fillText('  anomaly', tx + tw, cy)
        }
        ctx.globalAlpha = 1
      })
    },
    [upTo]
  )

  if (layout.nodes.length === 0 && full.nodes.length === 0) {
    return <p className="rounded-lg bg-slate-50 px-3 py-6 text-center text-sm text-slate-500">This incident has no graph.</p>
  }

  const modeButton = (mode: ReachMode, text: string) => (
    <button
      key={mode}
      type="button"
      aria-pressed={reachMode === mode}
      onClick={() => setReachMode(mode)}
      className={cn('rounded-md px-2 py-0.5', reachMode === mode ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-50')}
    >
      {text}
    </button>
  )

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={togglePlay} aria-label={playing ? 'Pause' : 'Play steps in order'}>
          {playing ? <Pause className="mr-1 h-3.5 w-3.5" /> : <Play className="mr-1 h-3.5 w-3.5" />}
          {playing ? 'Pause' : 'Play'}
        </Button>
        <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Show up to step">
          {layout.steps.map((n) => {
            const step = chain.find((s) => s.n === n)
            return (
              <button
                key={n}
                type="button"
                onClick={() => {
                  setPlaying(false)
                  setUpTo(n)
                }}
                aria-pressed={upTo === n}
                title={step?.action}
                className={cn(
                  'h-7 w-7 rounded-full font-mono text-xs font-bold text-white transition-opacity',
                  upTo != null && n > upTo && 'opacity-30'
                )}
                style={{ background: tacticColor(step?.tactic) }}
              >
                {n}
              </button>
            )
          })}
        </div>
        <Button size="sm" variant="ghost" onClick={reset} disabled={upTo == null && !playing}>
          <RotateCcw className="mr-1 h-3.5 w-3.5" /> All steps
        </Button>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {reachTotal > 0 && (
            <div role="group" aria-label="Reach next nodes" className="flex items-center rounded-lg border border-slate-200 p-0.5 text-xs">
              <span className="px-1.5 text-slate-500">Reach next</span>
              {reachTotal > DEFAULT_REACH_LIMIT && modeButton('top', `Top ${DEFAULT_REACH_LIMIT}`)}
              {modeButton('all', `All ${reachTotal}`)}
              {modeButton('off', 'Off')}
            </div>
          )}
          {supportingTotal > 0 && (
            <label className="flex items-center gap-1.5 text-xs text-slate-600">
              <input type="checkbox" checked={showSupporting} onChange={(e) => setShowSupporting(e.target.checked)} />
              Anomaly evidence ({supportingTotal})
            </label>
          )}
          <Button size="sm" variant="outline" onClick={fit} aria-label="Fit to view">
            <Maximize2 className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="outline" onClick={exportPng}>
            <Download className="mr-1 h-3.5 w-3.5" /> PNG
          </Button>
        </div>
      </div>

      <p className="min-h-5 text-sm text-slate-700" aria-live="polite">
        {current ? (
          <>
            <span className="font-mono font-bold">Step {current.n}.</span> {current.action}
          </>
        ) : (
          <span className="text-slate-500">
            All {layout.steps.length} steps shown. Press Play to walk through them, click an edge for its evidence or a
            node for everything about it.
          </span>
        )}
      </p>

      <div ref={wrapRef} className="overflow-hidden rounded-lg border border-slate-200 bg-slate-50/50">
        <ForceGraph2D<Placed, DrawnLink>
          ref={fgRef}
          graphData={data}
          width={width}
          height={height}
          backgroundColor={BACKGROUND}
          nodeId="id"
          nodeLabel={(n) => (n.more ? `${n.more.count} more hosts reachable next; click to show them` : `${n.label} · ${NODE_KIND_LABEL[n.kind] ?? n.kind} · zone ${n.zone}`)}
          nodeCanvasObject={drawNode}
          nodePointerAreaPaint={(n, color, ctx) => {
            ctx.beginPath()
            ctx.arc(n.x ?? 0, n.y ?? 0, n.radius + 4, 0, 2 * Math.PI)
            ctx.fillStyle = color
            ctx.fill()
          }}
          linkCurvature="curvature"
          linkColor={(l) => (linkVisible(l, upTo) || (l.dashed && upTo === lastStep) ? l.color : '#e2e8f0')}
          linkWidth={(l) => (upTo != null && l.step === upTo ? 3.5 : l.dashed ? 1 : l.supporting ? 1.2 : 2)}
          linkLineDash={(l) => (l.dashed ? [4, 4] : l.supporting ? [2, 2] : null)}
          linkDirectionalArrowLength={(l) => (l.dashed ? 4 : 6)}
          linkDirectionalArrowRelPos={0.97}
          linkLabel={(l) => (l.action ? `Step ${l.step}${l.supporting ? ' (anomaly)' : ''}: ${l.action}` : l.label)}
          linkCanvasObjectMode={() => 'after'}
          linkCanvasObject={drawLinkLabel}
          onNodeClick={(n) => (n.more ? setReachMode('all') : onNodeClick?.(String(n.id)))}
          onLinkClick={(l) => l.step != null && onStepClick?.(upTo != null && l.card ? upTo : l.step)}
          enableNodeDrag={false}
          cooldownTicks={0}
          warmupTicks={0}
          autoPauseRedraw={false}
          minZoom={0.2}
          maxZoom={6}
        />
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-500">
        {kinds.map((k) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: NODE_KIND_COLOR[k] }} />
            {NODE_KIND_LABEL[k]}
          </span>
        ))}
        {(['observed', 'inferred'] as const).filter((k) => hasReach[k]).map((k) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-dashed" style={{ borderColor: REACH_COLOR[k] }} />
            Reach next, {k}
          </span>
        ))}
        <span>
          Numbers and colours are the steps and their ATT&amp;CK tactics; node size is how important the asset is.
          {layout.hiddenReach > 0 &&
            ` ${layout.hiddenReach} more reachable ${layout.hiddenReach === 1 ? 'host is' : 'hosts are'} listed on the Reach next tab.`}
        </span>
      </div>
    </div>
  )
}

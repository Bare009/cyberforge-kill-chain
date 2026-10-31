import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D, { type ForceGraphMethods } from 'react-force-graph-2d'
import { Download, Maximize2, Pause, Play, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useElementWidth } from '@/hooks/useElementWidth'
import { saveBlob } from '@/lib/download'
import { cn } from '@/lib/utils'
import {
  NODE_KIND_COLOR,
  NODE_KIND_LABEL,
  REACH_COLOR,
  labelPoint,
  layoutPathGraph,
  linkVisible,
  type PathLink,
  type PathNode,
} from '@/lib/pathGraph'
import { tacticColor } from '@/lib/killchain'
import type { GraphEdge, GraphNode, NodeKind, Step } from '@/types/incident'

const PLAY_INTERVAL_MS = 1400
const HEIGHT = 440

/** react-force-graph replaces link ends with the node objects once it has laid them out. */
type Placed = PathNode & { x?: number; y?: number }
type DrawnLink = Omit<PathLink, 'source' | 'target'> & { source: string | Placed; target: string | Placed }

function end(v: string | Placed): Placed | null {
  return typeof v === 'object' && v !== null ? v : null
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
 * order the attacker reached them, one edge per numbered step, reach-next
 * drawn dashed. Play highlights steps 1..N in order.
 */
export function AttackPathGraph({ graph, chain, fileName, onNodeClick, onStepClick }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const fgRef = useRef<ForceGraphMethods<Placed, DrawnLink> | undefined>(undefined)
  const width = useElementWidth(wrapRef)
  const [upTo, setUpTo] = useState<number | null>(null)
  const [playing, setPlaying] = useState(false)

  const layout = useMemo(() => layoutPathGraph(graph, chain), [graph, chain])
  // Fresh objects for the library, which mutates them.
  const data = useMemo(
    () => ({ nodes: layout.nodes.map((n) => ({ ...n })) as Placed[], links: layout.links.map((l) => ({ ...l })) as DrawnLink[] }),
    [layout]
  )
  const lastStep = layout.steps[layout.steps.length - 1] ?? 0
  const current = upTo != null ? chain.find((s) => s.n === upTo) : undefined

  const fit = useCallback(() => fgRef.current?.zoomToFit(400, 60), [])
  useEffect(() => {
    const t = setTimeout(fit, 150)
    return () => clearTimeout(t)
  }, [fit, data, width])

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
        ctx.lineWidth = 2
        ctx.strokeStyle = node.color
        ctx.stroke()
        ctx.setLineDash([])
      } else {
        ctx.fillStyle = node.color
        ctx.fill()
        ctx.lineWidth = 1.5
        ctx.strokeStyle = '#ffffff'
        ctx.stroke()
      }
      const size = Math.max(10 / scale, 3.5)
      ctx.font = `600 ${size}px Inter, system-ui, sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      ctx.fillStyle = '#0f172a'
      ctx.fillText(node.label, x, y + node.radius + 3)
      ctx.font = `${size * 0.85}px Inter, system-ui, sans-serif`
      ctx.fillStyle = '#64748b'
      ctx.fillText(node.reach ? `reach next (${node.reach})` : NODE_KIND_LABEL[node.kind] ?? node.kind, x, y + node.radius + 4 + size)
      ctx.globalAlpha = 1
    },
    [upTo, lastStep]
  )

  const drawLinkLabel = useCallback(
    (link: DrawnLink, ctx: CanvasRenderingContext2D, scale: number) => {
      const s = end(link.source)
      const t = end(link.target)
      if (!s || !t || s.x == null || s.y == null || t.x == null || t.y == null) return
      const visible = linkVisible(link, upTo) || (link.dashed && upTo === lastStep)
      if (!visible && upTo != null) return
      const p = labelPoint(s.x, s.y, t.x, t.y, link.curvature)
      const size = Math.max(9 / scale, 3)
      ctx.font = `${link.step === upTo ? 700 : 500} ${size}px Inter, system-ui, sans-serif`
      const text = link.label
      const w = ctx.measureText(text).width
      ctx.fillStyle = 'rgba(255,255,255,0.92)'
      ctx.fillRect(p.x - w / 2 - 2, p.y - size / 2 - 1.5, w + 4, size + 3)
      ctx.fillStyle = link.dashed ? '#475569' : link.color
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(text, p.x, p.y)
    },
    [upTo, lastStep]
  )

  if (layout.nodes.length === 0) {
    return <p className="rounded-lg bg-slate-50 px-3 py-6 text-center text-sm text-slate-500">This incident has no graph.</p>
  }

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
        <div className="ml-auto flex gap-1">
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
          height={HEIGHT}
          backgroundColor="#f8fafc"
          nodeId="id"
          nodeLabel={(n) => `${n.label} · ${NODE_KIND_LABEL[n.kind] ?? n.kind} · zone ${n.zone}`}
          nodeCanvasObject={drawNode}
          nodePointerAreaPaint={(n, color, ctx) => {
            ctx.beginPath()
            ctx.arc(n.x ?? 0, n.y ?? 0, n.radius + 4, 0, 2 * Math.PI)
            ctx.fillStyle = color
            ctx.fill()
          }}
          linkCurvature="curvature"
          linkColor={(l) => (linkVisible(l, upTo) || (l.dashed && upTo === lastStep) ? l.color : '#cbd5e1')}
          linkWidth={(l) => (upTo != null && l.step === upTo ? 4 : l.dashed ? 1.5 : 2.5)}
          linkLineDash={(l) => (l.dashed ? [5, 4] : null)}
          linkDirectionalArrowLength={7}
          linkDirectionalArrowRelPos={0.92}
          linkLabel={(l) => (l.action ? `Step ${l.step}: ${l.action}` : l.label)}
          linkCanvasObjectMode={() => 'after'}
          linkCanvasObject={drawLinkLabel}
          onNodeClick={(n) => onNodeClick?.(String(n.id))}
          onLinkClick={(l) => l.step != null && onStepClick?.(l.step)}
          enableNodeDrag={false}
          cooldownTicks={0}
          warmupTicks={0}
          autoPauseRedraw={false}
          minZoom={0.3}
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
        <span>Edge colour is the step's ATT&amp;CK tactic; size is how important the asset is.</span>
      </div>
    </div>
  )
}

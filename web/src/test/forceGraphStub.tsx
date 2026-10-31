/**
 * Stand-in for react-force-graph-2d in tests: jsdom has no canvas, so this
 * renders each node and link as a button that fires the same callbacks.
 * Use with: vi.mock('react-force-graph-2d', () => import('@/test/forceGraphStub'))
 */
import { forwardRef, useImperativeHandle } from 'react'

interface StubProps {
  graphData: { nodes: { id: string; label?: string }[]; links: { label?: string; step?: number | null }[] }
  onNodeClick?: (node: unknown, event: unknown) => void
  onLinkClick?: (link: unknown, event: unknown) => void
  linkColor?: (link: unknown) => string
}

const Stub = forwardRef<unknown, StubProps>(function ForceGraphStub(props, ref) {
  useImperativeHandle(ref, () => ({ zoomToFit: () => undefined, centerAt: () => undefined, zoom: () => 1 }))
  return (
    <div data-testid="force-graph">
      {props.graphData.nodes.map((n) => (
        <button key={n.id} type="button" onClick={(e) => props.onNodeClick?.(n, e)}>
          node {n.id}
        </button>
      ))}
      {props.graphData.links.map((l, i) => (
        <button
          key={i}
          type="button"
          data-color={props.linkColor?.(l)}
          onClick={(e) => props.onLinkClick?.(l, e)}
        >
          edge {l.label}
        </button>
      ))}
    </div>
  )
})

export default Stub

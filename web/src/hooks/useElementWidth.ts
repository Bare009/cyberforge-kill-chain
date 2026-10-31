import { useEffect, useState, type RefObject } from 'react'

/** Width of an element in CSS pixels, kept up to date as it resizes (canvas graphs need a number). */
export function useElementWidth(ref: RefObject<HTMLElement | null>, fallback = 800): number {
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const measure = () => {
      const w = el.getBoundingClientRect().width
      if (w > 0) setWidth(Math.floor(w))
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return width
}

import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import { setDisplayTimeZone } from '@/lib/utils'

// Same clock as the app (MainLayout sets IST).
setDisplayTimeZone('Asia/Kolkata')

afterEach(() => {
  cleanup()
})

// recharts and react-force-graph measure their container; jsdom has no layout.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver

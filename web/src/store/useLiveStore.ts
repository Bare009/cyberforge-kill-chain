import { create } from 'zustand'
import type { LiveEvent } from '@/types/system'

const KEY = 'killchain.live.follow'
const MAX_FEED = 100

function initialFollow(): boolean {
  try {
    return globalThis.localStorage?.getItem(KEY) !== 'off'
  } catch {
    return true
  }
}

export type Connection = 'off' | 'connecting' | 'open' | 'error'

interface LiveState {
  /** Follow live updates: the app keeps a stream open and refreshes pages when the run changes. */
  follow: boolean
  setFollow: (v: boolean) => void
  connection: Connection
  setConnection: (c: Connection) => void
  /** Newest first. */
  feed: LiveEvent[]
  push: (e: LiveEvent) => void
  /** Incidents new or changed since the page was opened (incident number -> when). */
  changed: Record<number, string>
  clearChanged: () => void
}

export const useLiveStore = create<LiveState>((set) => ({
  follow: initialFollow(),
  setFollow: (v) => {
    try {
      globalThis.localStorage?.setItem(KEY, v ? 'on' : 'off')
    } catch {
      /* private mode: keep it for this tab only */
    }
    set({ follow: v, connection: v ? 'connecting' : 'off' })
  },
  connection: 'off',
  setConnection: (connection) => set({ connection }),
  feed: [],
  push: (e) =>
    set((s) => {
      if (s.feed.some((x) => x.id === e.id && x.type === e.type)) return s
      const changed = { ...s.changed }
      for (const n of [...(e.new_incidents ?? []), ...(e.changed_incidents ?? [])]) changed[n] = e.at
      return { feed: [e, ...s.feed].slice(0, MAX_FEED), changed }
    }),
  changed: {},
  clearChanged: () => set({ changed: {} }),
}))

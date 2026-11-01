import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { invalidateRunData } from '@/hooks/useJobs'
import { API_BASE_URL } from '@/lib/api'
import { useAppStore } from '@/store/useAppStore'
import { useLiveStore } from '@/store/useLiveStore'
import type { LiveEvent } from '@/types/system'

/**
 * Keeps GET /live/stream open while "follow live updates" is on. When the run's bundle
 * changes it refreshes every page's data and marks the changed incidents. Renders nothing.
 */
export function LiveListener() {
  const follow = useLiveStore((s) => s.follow)
  const push = useLiveStore((s) => s.push)
  const setConnection = useLiveStore((s) => s.setConnection)
  const notify = useAppStore((s) => s.addNotification)
  const qc = useQueryClient()

  useEffect(() => {
    if (!follow || typeof EventSource === 'undefined') {
      setConnection('off')
      return
    }
    setConnection('connecting')
    const es = new EventSource(`${API_BASE_URL}/live/stream`)
    const parse = (m: MessageEvent): LiveEvent | null => {
      try {
        return JSON.parse(m.data) as LiveEvent
      } catch {
        return null
      }
    }
    es.onopen = () => setConnection('open')
    es.onerror = () => setConnection(es.readyState === EventSource.CLOSED ? 'error' : 'connecting')
    es.addEventListener('hello', () => setConnection('open'))
    es.addEventListener('bundle', (m) => {
      const e = parse(m as MessageEvent)
      if (!e) return
      push(e)
      void qc.invalidateQueries()            // every page reloads its data from the new bundle
      const c = e.counts
      if (c && (c.new_incidents || c.changed_incidents || c.new_alerts)) {
        const parts = [
          c.new_incidents ? `${c.new_incidents} new incident${c.new_incidents === 1 ? '' : 's'}` : '',
          c.changed_incidents ? `${c.changed_incidents} changed` : '',
          c.new_alerts ? `${c.new_alerts} new alert${c.new_alerts === 1 ? '' : 's'}` : '',
        ].filter(Boolean)
        notify({ type: 'warning', message: `Live: ${parts.join(', ')}`, duration: 6000 })
      }
    })
    // The API switched to another run (an analysis finished, or someone picked a run): reload
    // everything. The stream then ends and EventSource reconnects to the new run's watcher.
    es.addEventListener('run', (m) => {
      const e = parse(m as MessageEvent)
      if (!e) return
      push(e)
      void invalidateRunData(qc)
      void qc.invalidateQueries({ queryKey: ['job'] })
    })
    es.addEventListener('status', (m) => {
      const e = parse(m as MessageEvent)
      if (!e) return
      push(e)
      void qc.invalidateQueries({ queryKey: ['live'] })
    })
    return () => es.close()
  }, [follow, push, setConnection, notify, qc])

  return null
}

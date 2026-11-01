import { useHealth } from '@/hooks/useHealth'
import { API_BASE_URL } from '@/lib/api'

export function StatusBar() {
  const { data, isError, isPending } = useHealth()

  const dot = isPending ? 'text-amber-500' : isError ? 'text-red-500' : 'text-green-500'
  const label = isPending ? 'Connecting to API...' : isError ? `API offline (${API_BASE_URL})` : 'API connected'

  return (
    <footer className="fixed bottom-0 left-0 right-0 z-40 h-8 border-t border-slate-200 bg-white px-4 flex items-center gap-4 text-xs font-mono text-slate-500">
      <span className="flex items-center gap-1.5">
        <span className={dot} aria-hidden>
          ●
        </span>
        {label}
      </span>
      {data && (
        <>
          <span>|</span>
          <span>
            {data.empty ? 'No run loaded' : `Run: ${data.run}`}
            {data.sample ? ' (sample)' : ''}
          </span>
          <span>|</span>
          <span>{data.counts.incidents} incidents</span>
          <span>|</span>
          <span>{data.counts.alerts} alerts</span>
        </>
      )}
      <span className="ml-auto">Times in IST</span>
    </footer>
  )
}

import { Link } from 'react-router-dom'
import { AlertCircle, Radio, RefreshCw } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { SeverityText } from '@/components/incident/badges'
import { KpiTile, PageTitle, TimeCell } from '@/components/views/shared'
import { useLiveStatus } from '@/hooks/useSystem'
import { apiErrorMessage } from '@/lib/api'
import { formatBytes } from '@/lib/format'
import { cn, formatFullTime } from '@/lib/utils'
import { useLiveStore, type Connection } from '@/store/useLiveStore'
import type { LiveEvent } from '@/types/system'

const STATE: Record<string, { label: string; tone: string }> = {
  running: { label: 'Running', tone: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
  stale: { label: 'No update for a while', tone: 'bg-amber-50 text-amber-800 border-amber-200' },
  stopped: { label: 'Stopped', tone: 'bg-slate-50 text-slate-600 border-slate-200' },
  'not started': { label: 'Not started', tone: 'bg-slate-50 text-slate-600 border-slate-200' },
}

const CONNECTION: Record<Connection, string> = {
  off: 'Not following',
  connecting: 'Connecting…',
  open: 'Connected: pages refresh as the run changes',
  error: 'Stream closed; retrying',
}

function FollowSwitch() {
  const follow = useLiveStore((s) => s.follow)
  const setFollow = useLiveStore((s) => s.setFollow)
  const connection = useLiveStore((s) => s.connection)
  return (
    <div className="flex items-center gap-3">
      <button
        role="switch"
        aria-checked={follow}
        aria-label="Follow live updates"
        onClick={() => setFollow(!follow)}
        className={cn('relative h-6 w-11 rounded-full transition-colors', follow ? 'bg-emerald-500' : 'bg-slate-300')}
      >
        <span className={cn('absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-[left]', follow ? 'left-[22px]' : 'left-0.5')} />
      </button>
      <div className="text-sm">
        <div className="font-medium text-slate-800">Follow live updates</div>
        <div className="flex items-center gap-1.5 text-xs text-slate-500">
          <span className={cn('h-1.5 w-1.5 rounded-full', connection === 'open' ? 'bg-emerald-500' : connection === 'error' ? 'bg-red-500' : 'bg-slate-400')} />
          {CONNECTION[connection]}
        </div>
      </div>
    </div>
  )
}

function EventRow({ e }: { e: LiveEvent }) {
  if (e.type === 'status') {
    return (
      <li className="flex items-start gap-3 border-b border-slate-50 px-4 py-2 text-xs">
        <span className="w-36 shrink-0 text-slate-500"><TimeCell iso={e.at} /></span>
        <span className="text-slate-700">Live process: {e.previous} → <span className="font-medium">{e.state}</span></span>
      </li>
    )
  }
  const c = e.counts
  return (
    <li className="space-y-1 border-b border-slate-50 px-4 py-2 text-xs">
      <div className="flex items-start gap-3">
        <span className="w-36 shrink-0 text-slate-500"><TimeCell iso={e.at} /></span>
        <span className="flex flex-wrap gap-x-3 gap-y-1 text-slate-700">
          {c && <span>{c.incidents} incidents, {c.alerts} alerts in the run</span>}
          {(e.new_incidents ?? []).map((n) => (
            <Link key={`n${n}`} to={`/incidents/${n}`} className="rounded border border-emerald-200 bg-emerald-50 px-1 font-mono text-emerald-800">
              new #{n}
            </Link>
          ))}
          {(e.changed_incidents ?? []).map((n) => (
            <Link key={`c${n}`} to={`/incidents/${n}`} className="rounded border border-blue-200 bg-blue-50 px-1 font-mono text-blue-800">
              changed #{n}
            </Link>
          ))}
          {(e.removed_incidents ?? []).length > 0 && <span className="text-slate-500">{e.removed_incidents!.length} removed</span>}
        </span>
      </div>
      {(e.new_alerts ?? []).length > 0 && (
        <ul className="ml-[9.75rem] space-y-0.5">
          {e.new_alerts!.slice(0, 8).map((a) => (
            <li key={a.alert_id} className="flex flex-wrap items-center gap-2 text-slate-600">
              <SeverityText severity={a.severity} />
              <span className="font-medium text-slate-800">{a.title}</span>
              <span className="font-mono text-slate-400">{a.src_ip ?? ''}{a.dst_ip ? ` → ${a.dst_ip}` : ''}</span>
              {a.incident_number != null && <Link to={`/incidents/${a.incident_number}`} className="font-mono text-blue-700">#{a.incident_number}</Link>}
            </li>
          ))}
          {e.new_alerts!.length > 8 && <li className="text-slate-400">and {e.new_alerts!.length - 8} more</li>}
        </ul>
      )}
    </li>
  )
}

export function Live() {
  const { data, isLoading, isError, error } = useLiveStatus()
  const feed = useLiveStore((s) => s.feed)
  // events seen on this page's stream first, then what the API remembers from before
  const seen = new Set(feed.map((e) => `${e.type}-${e.id}`))
  const events = [...feed, ...(data?.events ?? []).filter((e) => !seen.has(`${e.type}-${e.id}`))]
    .filter((e) => e.type !== 'hello')
    .sort((a, b) => b.id - a.id)
  const p = data?.process
  const st = STATE[data?.process_state ?? ''] ?? { label: data?.process_state ?? '—', tone: 'bg-slate-50 text-slate-600 border-slate-200' }
  const progress = p?.offset != null && p?.size ? Math.min(1, p.offset / p.size) : null

  return (
    <div className="space-y-5">
      <PageTitle icon={<Radio className="h-5 w-5" />} title="Live"
        subtitle="New log lines become alerts and incidents within seconds while the live process runs.">
        <FollowSwitch />
      </PageTitle>

      {isError && (
        <div role="alert" className="flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          <AlertCircle className="h-4 w-4" /> Could not load the live status: {apiErrorMessage(error)}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiTile loading={isLoading} label="Live process" value={<span className={cn('rounded border px-2 py-0.5 text-sm', st.tone)}>{st.label}</span>}
          hint={p?.updated_at ? `last update ${formatFullTime(p.updated_at)}` : undefined} />
        <KpiTile loading={isLoading} label="Lines per second" value={p?.lines_per_sec != null ? Number(p.lines_per_sec).toLocaleString() : '—'}
          hint={p?.lines_total != null ? `${Number(p.lines_total).toLocaleString()} lines read` : undefined} />
        <KpiTile loading={isLoading} label="Tail position"
          value={p?.offset != null ? formatBytes(Number(p.offset)) : '—'}
          hint={p?.source ? `${p.source}${p.size ? ` of ${formatBytes(Number(p.size))}` : ''}` : undefined} />
        <KpiTile loading={isLoading} label="Bundle reloads" value={data ? String(data.reloads) : '—'} icon={<RefreshCw className="h-4 w-4 text-slate-500" />}
          hint={data ? `checked every ${data.interval_s} s${data.watching ? '' : ' (watcher off)'}` : undefined} />
      </div>
      {progress != null && (
        <div className="h-1.5 overflow-hidden rounded-full bg-slate-100" aria-label="Tail progress">
          <div className="h-full bg-emerald-500" style={{ width: `${progress * 100}%` }} />
        </div>
      )}

      {data && data.process_state !== 'running' && (
        <Card>
          <CardContent className="space-y-1 p-4 text-sm text-slate-600">
            <p>
              The live process is not running, so nothing new arrives. Start it with{' '}
              <code className="rounded bg-slate-100 px-1 text-xs">{data.how_to_start}</code>.
            </p>
            <p className="text-xs text-slate-500">
              The API still watches the run folder: rerunning any pipeline stage and the bundle step updates every page here
              {data.watching ? '' : ' once the API runs with the watcher on (the default; not with --no-watch)'}.
            </p>
          </CardContent>
        </Card>
      )}
      {data?.last_error && (
        <p role="alert" className="text-xs text-amber-800">Last reload failed and will be retried: {data.last_error}</p>
      )}

      <div className="rounded-xl border border-slate-200 bg-white">
        <div className="flex items-center justify-between border-b border-slate-100 px-4 py-2">
          <h2 className="text-sm font-semibold text-slate-800">Changes</h2>
          <span className="text-xs text-slate-400">{data ? `${data.counts.incidents} incidents, ${data.counts.alerts} alerts now` : ''}</span>
        </div>
        {isLoading ? (
          <Skeleton className="m-3 h-20" />
        ) : events.length === 0 ? (
          <p className="px-4 py-10 text-center text-sm text-slate-400">No changes since the API started.</p>
        ) : (
          <ul aria-label="Live changes">{events.map((e) => <EventRow key={`${e.type}-${e.id}`} e={e} />)}</ul>
        )}
      </div>
    </div>
  )
}

import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, CheckCircle2, Circle, FileUp, Loader2, MinusCircle, Play, Square, UploadCloud, X, XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import { useHealth } from '@/hooks/useHealth'
import { invalidateRunData, useCancelJob, useCurrentJob, useRuns, useStartJob, useUploads } from '@/hooks/useJobs'
import { apiErrorMessage } from '@/lib/api'
import { formatBytes, formatSecs } from '@/lib/format'
import { isAbort, runNameFor, safeFileName, uploadFile, type UploadProgress } from '@/lib/upload'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store/useAppStore'
import type { Job, JobStage } from '@/types/jobs'

const STAGE_LABEL: Record<string, string> = {
  parse: 'Parse the log',
  prepare: 'Load events into DuckDB',
  detect: 'Detect (rules and anomalies)',
  correlate: 'Correlate alerts into incidents',
  chain: 'Build kill chains',
  reach: 'Reach next',
  score: 'Risk score',
  report: 'Reports',
  enrich: 'Threat intel',
  narrate: 'AI narrator',
  bundle: 'Bundle for the UI',
}

const DONE_TEXT: Record<string, string> = {
  ok: 'Done',
  ok_with_warnings: 'Done, with warnings',
  failed: 'Failed',
  no_events: 'No events in the file',
  cancelled: 'Cancelled',
  usage_error: 'Could not start',
}

const DISMISSED_KEY = 'killchain.analyse.dismissed'

/** Seconds since `iso`, ticking once a second while `on`. */
function useElapsed(iso: string | undefined, on: boolean): number | null {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!on) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [on])
  if (!iso) return null
  return Math.max(0, (now - Date.parse(iso)) / 1000)
}

function StageIcon({ status }: { status: JobStage['status'] }) {
  if (status === 'running') return <Loader2 className="h-4 w-4 animate-spin text-blue-600" aria-label="running" />
  if (status === 'ok') return <CheckCircle2 className="h-4 w-4 text-emerald-600" aria-label="done" />
  if (status === 'degraded') return <AlertTriangle className="h-4 w-4 text-amber-500" aria-label="degraded" />
  if (status === 'failed') return <XCircle className="h-4 w-4 text-red-600" aria-label="failed" />
  if (status === 'skipped' || status === 'cancelled') return <MinusCircle className="h-4 w-4 text-slate-300" aria-label={status} />
  return <Circle className="h-4 w-4 text-slate-200" aria-label="waiting" />
}

function StageList({ job }: { job: Job }) {
  return (
    <ol className="grid gap-x-6 gap-y-1 text-xs sm:grid-flow-col sm:grid-cols-2 sm:grid-rows-6" aria-label="Pipeline stages">
      {job.stages.map((s, i) => (
        <li key={s.name} className={cn('flex items-center gap-2', s.status === 'running' && 'font-semibold text-slate-900')}
          title={s.reason ?? undefined}>
          <StageIcon status={s.status} />
          <span className="font-mono text-slate-400">{i + 1}.</span>
          <span className={cn('flex-1 truncate', s.status === 'skipped' ? 'text-slate-400' : 'text-slate-700')}>
            {STAGE_LABEL[s.name] ?? s.name}
            {s.status === 'skipped' && s.reason ? <span className="text-slate-400"> (skipped)</span> : null}
          </span>
          <span className="font-mono text-slate-500">{s.wall_secs != null ? formatSecs(s.wall_secs) : ''}</span>
        </li>
      ))}
    </ol>
  )
}

function ParseBar({ job }: { job: Job }) {
  const p = job.parse
  const parse = job.stages.find((s) => s.name === 'parse')
  if (parse?.status !== 'running') return null
  const sizeGib = job.file_bytes / 2 ** 30
  const left = p.phase === 'parsing' && p.secs && p.gib > 0 ? ((sizeGib - p.gib) * p.secs) / p.gib : null
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-slate-600">
        <span>
          {p.phase === 'counting' || p.phase == null
            ? `Counting lines in ${formatBytes(job.file_bytes)}…`
            : `Parsed ${p.gib.toFixed(2)} of ${sizeGib.toFixed(2)} GiB (${p.pct.toFixed(0)}%)`}
        </span>
        {left != null && <span>about {formatSecs(left)} left in this stage</span>}
      </div>
      <Progress value={p.pct} aria-label="Parse progress" />
    </div>
  )
}

function Running({ job, onCancel, cancelling }: { job: Job; onCancel: () => void; cancelling: boolean }) {
  const elapsed = useElapsed(job.started_at, true) ?? job.elapsed_secs
  const done = job.stages.filter((s) => ['ok', 'degraded', 'skipped', 'failed'].includes(s.status)).length
  const now = job.current === 'loading' ? 'Loading the results into the API' : job.current ? STAGE_LABEL[job.current] ?? job.current : 'Starting'
  return (
    <div className="space-y-3" aria-live="polite">
      <div className="flex flex-wrap items-center gap-3">
        <Loader2 className="h-5 w-5 animate-spin text-blue-600" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-900">
            Analysing {job.file} <span className="font-normal text-slate-500">({formatBytes(job.file_bytes)}) into run {job.run}</span>
          </p>
          <p className="text-xs text-slate-500">
            Stage {Math.min(done + 1, job.stages.length)} of {job.stages.length}: {now} · {formatSecs(elapsed)} so far
            {job.upload_secs != null && ` · upload took ${formatSecs(job.upload_secs)}`}
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={onCancel} disabled={cancelling || job.current === 'loading'}>
          <Square className="mr-1 h-3.5 w-3.5" /> Cancel
        </Button>
      </div>
      <Progress value={(100 * done) / job.stages.length} aria-label="Stages done" indicatorClassName="bg-emerald-500" />
      <ParseBar job={job} />
      <StageList job={job} />
      <details className="text-xs">
        <summary className="cursor-pointer text-slate-500">Pipeline output</summary>
        <pre className="mt-1 max-h-48 overflow-auto rounded-lg bg-slate-900 p-2 font-mono text-[11px] leading-snug text-slate-100">
          {job.tail.join('\n') || 'waiting for output…'}
        </pre>
      </details>
    </div>
  )
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2" aria-label={label}>
      <div className="text-lg font-bold text-slate-900">{value}</div>
      <div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      {hint && <div className="text-xs text-slate-400">{hint}</div>}
    </div>
  )
}

function Finished({ job, onDismiss, onAgain }: { job: Job; onDismiss: () => void; onAgain: () => void }) {
  const r = job.result
  const ok = job.state === 'ok' || job.state === 'ok_with_warnings'
  const processing = r?.wall_secs ?? job.elapsed_secs
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-start gap-3">
        {ok ? <CheckCircle2 className="mt-0.5 h-5 w-5 text-emerald-600" /> : <XCircle className="mt-0.5 h-5 w-5 text-red-600" />}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-900">
            {DONE_TEXT[job.state] ?? job.state}: {job.file} <span className="font-normal text-slate-500">({formatBytes(job.file_bytes)}) into run {job.run}</span>
          </p>
          <p className="text-xs text-slate-500">
            {ok && job.switched ? 'The dashboard and every page now show this run.' : ok ? 'Pick the run above to see it.' : ''}
            {job.error && <span className="text-red-700"> {job.error}</span>}
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={onAgain}><FileUp className="mr-1 h-3.5 w-3.5" /> Analyse another log</Button>
        <Button size="icon" variant="ghost" className="h-8 w-8" aria-label="Hide" onClick={onDismiss}><X className="h-4 w-4" /></Button>
      </div>
      {r && ok && (
        <div className="grid grid-cols-2 gap-2 md:grid-cols-6">
          <Stat label="Incidents" value={(r.incidents ?? 0).toLocaleString()} hint={r.critical_incidents ? `${r.critical_incidents} critical` : undefined} />
          <Stat label="Alerts" value={(r.alerts ?? 0).toLocaleString()} hint={r.unexplained != null ? `${r.unexplained} unexplained` : undefined} />
          <Stat label="Events" value={r.events != null ? r.events.toLocaleString() : '—'} hint={r.lines != null ? `${r.lines.toLocaleString()} lines` : undefined} />
          <Stat label="Upload" value={job.upload_secs != null ? formatSecs(job.upload_secs) : '—'} hint={job.upload_secs == null ? 'file was on the server' : undefined} />
          <Stat label="Processing" value={formatSecs(processing)} hint={r.peak_rss_mb ? `peak ${(r.peak_rss_mb / 1024).toFixed(1)} GB memory` : undefined} />
          <Stat label="Total" value={formatSecs((job.upload_secs ?? 0) + (processing ?? 0))} hint="upload + processing" />
        </div>
      )}
      <StageList job={job} />
      {r?.warnings?.length ? (
        <ul className="list-disc space-y-0.5 pl-5 text-xs text-amber-700">{r.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
      ) : null}
      {!ok && job.tail.length > 0 && (
        <pre className="max-h-48 overflow-auto rounded-lg bg-slate-900 p-2 font-mono text-[11px] leading-snug text-slate-100">{job.tail.join('\n')}</pre>
      )}
      {ok && job.switched && (
        <p className="text-xs"><Link to="/incidents" className="text-blue-700 hover:underline">Open the incidents</Link></p>
      )}
    </div>
  )
}

interface UploadState {
  file: File
  name: string
  progress: UploadProgress | null
}

/**
 * "Analyse a new log" on the Dashboard: upload a log (or pick one already on the server), run
 * the whole pipeline on it with live progress, and switch every page to the new run.
 */
export function AnalyseLog() {
  const qc = useQueryClient()
  const notify = useAppStore((s) => s.addNotification)
  const current = useCurrentJob()
  const uploads = useUploads()
  const runs = useRuns()
  const health = useHealth()
  const start = useStartJob()
  const cancel = useCancelJob()

  const [showForm, setShowForm] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [serverFile, setServerFile] = useState('')
  const [saveAs, setSaveAs] = useState('')
  const [runName, setRunName] = useState('')
  const [online, setOnline] = useState(true)
  const [ai, setAi] = useState<boolean | null>(null)
  const [workers, setWorkers] = useState<number | null>(null)
  const [uploading, setUploading] = useState<UploadState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [dismissed, setDismissed] = useState(() => localStorage.getItem(DISMISSED_KEY) ?? '')
  const abort = useRef<AbortController | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const lastState = useRef<Record<string, string>>({})

  const job = current.data?.job ?? null
  const enabled = current.data?.enabled !== false && uploads.data?.enabled !== false
  const aiAvailable = !!health.data?.llm?.enabled && (health.data?.llm?.configured.length ?? 0) > 0
  const useAi = ai ?? aiAvailable
  const taken = (runs.data?.runs ?? []).map((r) => r.name)

  // When a job finishes and the API switched to its run, every page reloads its data.
  useEffect(() => {
    if (!job) return
    const before = lastState.current[job.id]
    lastState.current[job.id] = job.state
    if (before === 'running' && job.state !== 'running') {
      void qc.invalidateQueries({ queryKey: ['uploads'] })
      void qc.invalidateQueries({ queryKey: ['runs'] })
      if (job.switched) {
        void invalidateRunData(qc)
        notify({ type: 'success', message: `Run ${job.run} is ready: ${job.result?.incidents ?? 0} incidents`, duration: 8000 })
      } else if (job.state !== 'cancelled') {
        notify({ type: 'error', message: `Analysis of ${job.file} ${DONE_TEXT[job.state]?.toLowerCase() ?? job.state}`, duration: 8000 })
      }
    }
  }, [job, qc, notify])

  const choose = (f: File | null) => {
    setError(null)
    setFile(f)
    setServerFile('')
    if (f) {
      const name = safeFileName(f.name)
      setSaveAs(name)
      setRunName(runNameFor(name, taken))
    }
  }
  const chooseServerFile = (name: string) => {
    setError(null)
    setServerFile(name)
    setFile(null)
    if (name) setRunName(runNameFor(name, taken))
  }

  const go = async () => {
    setError(null)
    const name = file ? saveAs.trim() : serverFile
    if (!name || !runName.trim()) return
    let uploadSecs: number | null = null
    if (file) {
      const ctrl = new AbortController()
      abort.current = ctrl
      setUploading({ file, name, progress: null })
      try {
        const res = await uploadFile(file, name, {
          signal: ctrl.signal,
          onProgress: (p) => setUploading((u) => (u ? { ...u, progress: p } : u)),
        })
        uploadSecs = res.already ? null : res.secs
        if (res.already) notify({ type: 'success', message: `${name} was already on the server; not sent again`, duration: 5000 })
      } catch (err) {
        setUploading(null)
        if (!isAbort(err)) setError(apiErrorMessage(err, 'Upload failed'))
        return
      }
      setUploading(null)
    }
    try {
      await start.mutateAsync({
        file: name, run: runName.trim(), offline: !online, no_llm: !useAi,
        workers: workers ?? uploads.data?.defaults.workers, upload_secs: uploadSecs,
      })
      setShowForm(false)
      setFile(null)
      setServerFile('')
      void qc.invalidateQueries({ queryKey: ['uploads'] })
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not start the analysis'))
    }
  }

  const stopUpload = () => abort.current?.abort()

  const dismiss = (id: string) => {
    localStorage.setItem(DISMISSED_KEY, id)
    setDismissed(id)
  }

  if (!enabled) return null
  const running = job?.state === 'running'
  const finished = job && !running && job.id !== dismissed && !showForm

  let body: React.ReactNode
  if (running) {
    body = <Running job={job} onCancel={() => cancel.mutate()} cancelling={cancel.isPending} />
  } else if (uploading) {
    const p = uploading.progress
    const pct = p ? (100 * p.sent) / p.total : 0
    const left = p?.bytesPerSec ? (p.total - p.sent) / p.bytesPerSec : null
    body = (
      <div className="space-y-2" aria-live="polite">
        <div className="flex flex-wrap items-center gap-3">
          <UploadCloud className="h-5 w-5 text-blue-600" />
          <p className="min-w-0 flex-1 text-sm font-semibold text-slate-900">
            Uploading {uploading.name}{' '}
            <span className="font-normal text-slate-500">
              {formatBytes(p?.sent ?? 0)} of {formatBytes(uploading.file.size)}
              {p?.bytesPerSec ? ` · ${formatBytes(p.bytesPerSec)}/s` : ''}
              {left != null ? ` · about ${formatSecs(left)} left` : ''}
              {p?.resumedFrom ? ` · resumed at ${formatBytes(p.resumedFrom)}` : ''}
            </span>
          </p>
          <Button size="sm" variant="outline" onClick={stopUpload}><Square className="mr-1 h-3.5 w-3.5" /> Stop</Button>
        </div>
        <Progress value={pct} aria-label="Upload progress" />
        <p className="text-xs text-slate-400">Stopped or cut off? Pick the same file again and the upload carries on where it stopped. Processing starts when it is complete.</p>
      </div>
    )
  } else if (finished) {
    body = <Finished job={job} onDismiss={() => dismiss(job.id)} onAgain={() => setShowForm(true)} />
  } else {
    const files = uploads.data?.files ?? []
    const ready = (file ? !!saveAs.trim() : !!serverFile) && !!runName.trim() && !start.isPending
    body = (
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <FileUp className="h-4 w-4 text-blue-600" />
          <h2 className="flex-1 text-sm font-semibold text-slate-800">Analyse a new log</h2>
          {job && job.id !== dismissed && (
            <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Back to the last result</Button>
          )}
        </div>
        <div
          role="button"
          tabIndex={0}
          aria-label="Choose a log file"
          onClick={() => inputRef.current?.click()}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); choose(e.dataTransfer.files?.[0] ?? null) }}
          className={cn('flex cursor-pointer flex-col items-center gap-1 rounded-xl border-2 border-dashed px-4 py-5 text-center text-sm',
            dragging ? 'border-blue-500 bg-blue-50' : 'border-slate-200 hover:border-blue-300 hover:bg-slate-50')}
        >
          <UploadCloud className="h-6 w-6 text-slate-400" />
          {file ? (
            <span className="font-medium text-slate-900">{file.name} <span className="font-normal text-slate-500">({formatBytes(file.size)})</span></span>
          ) : (
            <span className="text-slate-600">Drop a FortiGate log here or <span className="text-blue-700 underline">choose a file</span>. Files of many GB are fine.</span>
          )}
          <input ref={inputRef} type="file" className="hidden" data-testid="log-file" onChange={(e) => choose(e.target.files?.[0] ?? null)} />
        </div>
        {files.length > 0 && (
          <label className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
            Or use a log already on the server:
            <select className="h-8 rounded-md border border-slate-200 bg-white px-2 text-xs" value={serverFile}
              onChange={(e) => chooseServerFile(e.target.value)} aria-label="Log on the server">
              <option value="">choose…</option>
              {files.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.name} ({formatBytes(f.size)}){f.runs.length ? ` · run ${f.runs.join(', ')}` : ''}
                </option>
              ))}
            </select>
          </label>
        )}
        {(file || serverFile) && (
          <div className="grid gap-3 md:grid-cols-4">
            {file && (
              <label className="space-y-1 text-xs text-slate-600">
                Save on the server as
                <Input value={saveAs} onChange={(e) => setSaveAs(safeFileName(e.target.value))} aria-label="Save as" />
              </label>
            )}
            <label className="space-y-1 text-xs text-slate-600">
              Run name
              <Input value={runName} onChange={(e) => setRunName(e.target.value.replace(/[^A-Za-z0-9._-]/g, '_'))} aria-label="Run name" />
              {taken.includes(runName) && <span className="text-amber-700">A run of this name exists; pick another.</span>}
            </label>
            <label className="space-y-1 text-xs text-slate-600">
              Parser processes
              <Input type="number" min={1} max={64} value={workers ?? uploads.data?.defaults.workers ?? 4}
                onChange={(e) => setWorkers(Math.max(1, Number(e.target.value) || 1))} aria-label="Parser processes" />
            </label>
            <div className="space-y-1.5 text-xs text-slate-600">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={online} onChange={(e) => setOnline(e.target.checked)} />
                Look up IPs and domains online (OTX)
              </label>
              <label className={cn('flex items-center gap-2', !aiAvailable && 'text-slate-400')} title={aiAvailable ? undefined : 'No LLM key configured on the server'}>
                <input type="checkbox" checked={useAi && aiAvailable} disabled={!aiAvailable} onChange={(e) => setAi(e.target.checked)} />
                AI-written reports{!aiAvailable && ' (no LLM key)'}
              </label>
            </div>
          </div>
        )}
        {error && <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700">{error}</p>}
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={() => void go()} disabled={!ready || taken.includes(runName)}>
            <Play className="mr-1 h-4 w-4" /> {file ? 'Upload and analyse' : 'Analyse'}
          </Button>
          <span className="text-xs text-slate-400">
            Runs every stage, parse to bundle, then shows the new run here.
            {uploads.data?.free_bytes != null && ` ${formatBytes(uploads.data.free_bytes)} free on the server.`}
          </span>
        </div>
      </div>
    )
  }

  return (
    <Card className={cn(running && 'border-blue-200')}>
      <CardContent className="p-4">{body}</CardContent>
    </Card>
  )
}

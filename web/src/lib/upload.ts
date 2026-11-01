import axios from 'axios'
import { api } from '@/lib/api'
import type { UploadStatus } from '@/types/jobs'

/**
 * Chunked, resumable upload of one log file to POST /uploads/{name}.
 *
 * A file of many GB goes in 128 MB chunks, each appended where the server's copy ends. The
 * server says where that is (GET /uploads/{name}, or a 409 with `received`), so an upload cut
 * off by a reload or a dropped connection carries on from there when the same file is picked.
 */
export const CHUNK_BYTES = 128 * 2 ** 20
const RETRIES = 5
const PROGRESS_EVERY_MS = 250

export interface UploadProgress {
  sent: number
  total: number
  /** Bytes the server already had when this upload started (a resume). */
  resumedFrom: number
  bytesPerSec: number | null
}

/** "My log (1).txt" -> "My_log_1_.txt": the characters the API accepts in a file name. */
export function safeFileName(name: string): string {
  let n = name.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '')
  if (n.endsWith('.part')) n += '_'
  return n.slice(0, 128) || 'upload.log'
}

/** A run name from a file name that no existing run has: "firex-13G.log" -> "firex-13G" (or "firex-13G-2"). */
export function runNameFor(fileName: string, taken: Iterable<string>): string {
  const used = new Set(taken)
  const stem = (fileName.replace(/\.[^.]*$/, '').replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '')
    || 'upload').slice(0, 60)
  if (!used.has(stem)) return stem
  for (let i = 2; ; i++) if (!used.has(`${stem}-${i}`)) return `${stem}-${i}`
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => {
      clearTimeout(t)
      reject(new DOMException('Upload stopped', 'AbortError'))
    }, { once: true })
  })

export function isAbort(err: unknown): boolean {
  return axios.isCancel(err) || (err instanceof DOMException && err.name === 'AbortError')
}

export async function uploadStatus(name: string): Promise<UploadStatus> {
  return (await api.get<UploadStatus>(`/uploads/${encodeURIComponent(name)}`)).data
}

/**
 * Upload `file` as `name`. Resolves with `already` when the server had the whole file, and the
 * seconds this upload took. Rejects on abort (see isAbort) or a server refusal (no space, a
 * different file of that name).
 */
export async function uploadFile(file: File, name: string, opts: {
  signal?: AbortSignal
  onProgress?: (p: UploadProgress) => void
  chunkBytes?: number
} = {}): Promise<{ already: boolean; secs: number }> {
  const total = file.size
  const chunk = opts.chunkBytes ?? CHUNK_BYTES
  const t0 = performance.now()
  const st = await uploadStatus(name)
  if (st.complete) {
    if (st.size === total) return { already: true, secs: 0 }
    throw new Error(`A different file named ${name} is already on the server (${st.size?.toLocaleString()} bytes). Save yours under another name.`)
  }
  let offset = st.received <= total ? st.received : 0
  if (st.received > total) await api.post(`/uploads/${encodeURIComponent(name)}/discard`)
  const resumedFrom = offset
  let lastReport = 0
  const report = (sent: number, force = true) => {
    const now = performance.now()
    if (!force && now - lastReport < PROGRESS_EVERY_MS) return      // re-rendering on every event slows the upload
    lastReport = now
    const secs = (now - t0) / 1000
    opts.onProgress?.({ sent, total, resumedFrom, bytesPerSec: secs > 0.5 ? (sent - resumedFrom) / secs : null })
  }
  report(offset)
  let failures = 0
  while (offset < total) {
    const end = Math.min(offset + chunk, total)
    try {
      const res = await api.post<UploadStatus>(`/uploads/${encodeURIComponent(name)}`, file.slice(offset, end), {
        params: { offset, total },
        headers: { 'Content-Type': 'application/octet-stream' },
        timeout: 10 * 60_000,
        signal: opts.signal,
        onUploadProgress: (e) => report(offset + (e.loaded ?? 0), false),
      })
      offset = res.data.complete ? total : res.data.received
      failures = 0
      report(offset)
    } catch (err) {
      if (isAbort(err) || opts.signal?.aborted) throw err
      if (axios.isAxiosError(err) && err.response?.status === 409) {
        const received = (err.response.data as { received?: unknown } | undefined)?.received
        if (typeof received === 'number') {      // the server is somewhere else: carry on from there
          offset = received
          continue
        }
        throw err
      }
      if (axios.isAxiosError(err) && err.response) throw err    // refused (no space, bad name, ...)
      if (++failures > RETRIES) throw err
      await sleep(1000 * 2 ** (failures - 1), opts.signal)      // a dropped connection: try again
      offset = (await uploadStatus(name)).received
    }
  }
  return { already: false, secs: (performance.now() - t0) / 1000 }
}

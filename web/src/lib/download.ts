import { api } from '@/lib/api'

// Exports can take a while for large alert sets; allow more than the 25 s default.
const EXPORT_TIMEOUT_MS = 180_000

/** Save a Blob as a file via a temporary object URL. */
export function saveBlob(data: Blob, filename: string): void {
  const url = URL.createObjectURL(data)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
}

/**
 * Download an API export through the authenticated client (a plain link would
 * not carry the bearer token). Array params are sent as repeated keys, which is
 * what FastAPI's list query parameters expect.
 */
export async function downloadFromApi(
  path: string,
  params: Record<string, string | number | boolean | string[] | null | undefined>,
  filename: string
): Promise<void> {
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v == null || v === '') continue
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x))
    else sp.append(k, String(v))
  }
  const { data } = await api.get<Blob>(path, {
    params: sp,
    responseType: 'blob',
    timeout: EXPORT_TIMEOUT_MS,
  })
  saveBlob(data, filename)
}

/** Readable message from a failed blob download (FastAPI puts `detail` in a JSON body). */
export async function downloadErrorMessage(e: unknown, fallback: string): Promise<string> {
  const resp = (e as { response?: { data?: unknown } } | null)?.response
  if (resp?.data instanceof Blob) {
    try {
      const body = JSON.parse(await resp.data.text()) as { detail?: unknown }
      if (typeof body.detail === 'string') return body.detail
    } catch {
      /* not JSON */
    }
  }
  return e instanceof Error ? e.message : fallback
}

export function fileStamp(d = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`
}

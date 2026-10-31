import axios from 'axios'

/**
 * Client for `killchain/api`. No login: the API is local and read-only apart
 * from the agents and the rule writer.
 *
 * VITE_API_URL is the API's address with no trailing slash. In Docker the web
 * container proxies `/api` to the API, so the build sets it to `/api`.
 */
export const API_BASE_URL =
  import.meta.env.VITE_API_URL?.replace(/\/$/, '') || 'http://localhost:8000'

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 25_000,
})

/** Readable message from a failed request (FastAPI puts `detail` in the body). */
export function apiErrorMessage(err: unknown, fallback = 'Request failed'): string {
  if (axios.isAxiosError(err)) {
    if (!err.response) return `Cannot reach the API at ${API_BASE_URL}`
    const detail = (err.response.data as { detail?: unknown } | undefined)?.detail
    if (typeof detail === 'string') return detail
    return `${fallback} (HTTP ${err.response.status})`
  }
  return err instanceof Error ? err.message : fallback
}

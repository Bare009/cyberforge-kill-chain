/**
 * Response shapes of killchain/api that are not part of contracts B and C
 * (those live in docs/contracts.md). Filled in as P11 adds endpoints.
 */

/** GET /health */
export interface HealthResponse {
  status: 'ok' | 'degraded'
  run: string
  sample: boolean
  counts: {
    incidents: number
    alerts: number
    events?: number
  }
}

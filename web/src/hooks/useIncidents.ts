import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Incident, IncidentList, IncidentPath } from '@/types/incident'

export interface IncidentFilters {
  severity?: number
  tactic?: string
  technique?: string
  entity?: string
  q?: string
  limit?: number
  offset?: number
}

/** Drop empty values so the URL only carries the filters in use. */
function cleanParams(f: IncidentFilters): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(f)) {
    if (v === undefined || v === null || v === '') continue
    out[k] = typeof v === 'string' ? v.trim() : v
  }
  return out
}

/** GET /incidents, worst first. */
export function useIncidents(filters: IncidentFilters = {}) {
  const params = cleanParams(filters)
  return useQuery({
    queryKey: ['incidents', params],
    queryFn: async () => (await api.get<IncidentList>('/incidents', { params })).data,
    placeholderData: keepPreviousData,
  })
}

/** GET /incidents/{id}: the full incident. */
export function useIncident(id: string | undefined) {
  return useQuery({
    queryKey: ['incident', id],
    queryFn: async () => (await api.get<Incident>(`/incidents/${encodeURIComponent(id!)}`)).data,
    enabled: !!id,
    retry: false,
  })
}

/** GET /incidents/{id}/path: chain, graph and reach next. */
export function useIncidentPath(id: string | undefined) {
  return useQuery({
    queryKey: ['incident', id, 'path'],
    queryFn: async () => (await api.get<IncidentPath>(`/incidents/${encodeURIComponent(id!)}/path`)).data,
    enabled: !!id,
    retry: false,
  })
}

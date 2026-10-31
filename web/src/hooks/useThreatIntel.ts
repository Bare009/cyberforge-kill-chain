import { keepPreviousData, useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { TiIndicatorDetail, TiIndicatorList, TiLookupResult, TiStatus } from '@/types/ti'

export interface TiFilters {
  verdict?: string
  kind?: string
  q?: string
  sendable?: boolean
}

export function useTiStatus() {
  return useQuery({
    queryKey: ['ti', 'status'],
    queryFn: async () => (await api.get<TiStatus>('/ti/status')).data,
  })
}

export function useTiIndicators(filters: TiFilters) {
  const params: Record<string, string | boolean> = {}
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== '') params[k] = typeof v === 'string' ? v.trim() : v
  }
  return useQuery({
    queryKey: ['ti', 'indicators', params],
    queryFn: async () => (await api.get<TiIndicatorList>('/ti/indicators', { params })).data,
    placeholderData: keepPreviousData,
  })
}

export function useTiIndicator(value: string | null) {
  return useQuery({
    queryKey: ['ti', 'indicator', value],
    queryFn: async () => (await api.get<TiIndicatorDetail>(`/ti/indicators/${encodeURIComponent(value!)}`)).data,
    enabled: !!value,
    retry: false,
  })
}

/** POST /ti/lookup: an on-demand lookup (cached by the API; private values are never sent). */
export function useTiLookup() {
  return useMutation({
    mutationFn: async (value: string) => (await api.post<TiLookupResult>('/ti/lookup', { value })).data,
  })
}

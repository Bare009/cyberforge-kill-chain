import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AlertList, DashboardSummary, RuleDetail, RuleList, UnexplainedList } from '@/types/views'

function clean(filters: Record<string, string | number | undefined>): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== '') out[k] = typeof v === 'string' ? v.trim() : v
  }
  return out
}

export function useDashboard() {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: async () => (await api.get<DashboardSummary>('/dashboard/summary')).data,
  })
}

export interface AlertFilters {
  incident?: string
  technique?: string
  tactic?: string
  rule?: string
  layer?: string
  severity?: number
  entity?: string
  q?: string
  sort?: string
  limit?: number
  offset?: number
}

export function useAlerts(filters: AlertFilters, enabled = true) {
  const params = clean(filters as Record<string, string | number | undefined>)
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: async () => (await api.get<AlertList>('/alerts', { params })).data,
    placeholderData: keepPreviousData,
    enabled,
  })
}

export function useUnexplained(enabled = true) {
  return useQuery({
    queryKey: ['unexplained'],
    queryFn: async () => (await api.get<UnexplainedList>('/unexplained')).data,
    enabled,
  })
}

export function useRules(filters: { layer?: string; q?: string }) {
  const params = clean(filters)
  return useQuery({
    queryKey: ['rules', params],
    queryFn: async () => (await api.get<RuleList>('/rules', { params })).data,
    placeholderData: keepPreviousData,
  })
}

export function useRule(id: string | null) {
  return useQuery({
    queryKey: ['rule', id],
    queryFn: async () => (await api.get<RuleDetail>(`/rules/${encodeURIComponent(id!)}`)).data,
    enabled: !!id,
    retry: false,
  })
}

import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { LiveStatus, SystemResponse } from '@/types/system'

export function useSystem() {
  return useQuery({
    queryKey: ['system'],
    queryFn: async () => (await api.get<SystemResponse>('/system')).data,
    refetchInterval: 30_000,
  })
}

export function useLiveStatus() {
  return useQuery({
    queryKey: ['live', 'status'],
    queryFn: async () => (await api.get<LiveStatus>('/live/status')).data,
    refetchInterval: 5_000,
  })
}

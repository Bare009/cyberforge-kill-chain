import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { HealthResponse } from '@/types/api'

/** API status for the status bar; polls every 15 s and never retries noisily. */
export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: async () => (await api.get<HealthResponse>('/health', { timeout: 5_000 })).data,
    refetchInterval: 15_000,
    retry: false,
  })
}

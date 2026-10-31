// Copied from AI-SOC web_app/frontend/src/hooks/useSettingsData.ts (SIEM integration hooks only).
import { useQuery } from '@tanstack/react-query'
import { fetchIngestAgents, fetchSiemIntegrations, fetchSiemVendors } from '@/lib/connectors-api'

/** Query key for the connector list; exported so mutations can invalidate it. */
export const SIEM_INTEGRATIONS_KEY = ['settings', 'siem-integrations'] as const

export function useSiemIntegrationsQuery() {
  return useQuery({
    queryKey: SIEM_INTEGRATIONS_KEY,
    queryFn: fetchSiemIntegrations,
    // Rows carry live ingest counters, so refresh often enough that a freshly
    // connected source visibly starts receiving without a manual reload.
    staleTime: 10_000,
    refetchInterval: 30_000,
  })
}

export function useSiemVendorsQuery() {
  return useQuery({
    queryKey: ['settings', 'siem-vendors'],
    queryFn: fetchSiemVendors,
    // Static catalog shipped with the backend — no need to re-fetch.
    staleTime: Infinity,
  })
}

export function useIngestAgentsQuery(connectorId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: ['settings', 'siem-integrations', connectorId, 'agents'],
    queryFn: () => fetchIngestAgents(connectorId as string),
    enabled: enabled && Boolean(connectorId),
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

// Copied from AI-SOC web_app/frontend/src/lib/auth-api.ts (SIEM integration calls only),
// using killchain's API client (no auth token).
import type {
  CreateSiemIntegrationPayload,
  IngestAgentsResponse,
  SiemIntegrationRow,
  SiemIntegrationSecretResponse,
  SiemIntegrationsResponse,
  SiemVendorsResponse,
  UpdateSiemIntegrationPayload,
} from '@/types/connectors'
import { api } from './api'

export async function fetchSiemVendors(): Promise<SiemVendorsResponse> {
  const { data } = await api.get<SiemVendorsResponse>('/settings/siem-vendors')
  return data
}

export async function fetchSiemIntegrations(): Promise<SiemIntegrationsResponse> {
  const { data } = await api.get<SiemIntegrationsResponse>('/settings/siem-integrations')
  return data
}

/** Returns the connector plus its one-time `secret`. The secret is not retrievable later. */
export async function createSiemIntegration(
  payload: CreateSiemIntegrationPayload
): Promise<SiemIntegrationSecretResponse> {
  const { data } = await api.post<SiemIntegrationSecretResponse>(
    '/settings/siem-integrations',
    payload
  )
  return data
}

export async function updateSiemIntegration(
  connectorId: string,
  payload: UpdateSiemIntegrationPayload
): Promise<SiemIntegrationRow> {
  const { data } = await api.patch<SiemIntegrationRow>(
    `/settings/siem-integrations/${connectorId}`,
    payload
  )
  return data
}

/** Issues a new secret. The previous one stops working immediately. */
export async function rotateSiemIntegrationSecret(
  connectorId: string
): Promise<SiemIntegrationSecretResponse> {
  const { data } = await api.post<SiemIntegrationSecretResponse>(
    `/settings/siem-integrations/${connectorId}/rotate-secret`
  )
  return data
}

export async function deleteSiemIntegration(connectorId: string): Promise<void> {
  await api.delete(`/settings/siem-integrations/${connectorId}`)
}

/** API pull connectors: run on the collector's next tick instead of waiting for the interval. */
export async function pollSiemIntegrationNow(connectorId: string): Promise<SiemIntegrationRow> {
  const { data } = await api.post<SiemIntegrationRow>(
    `/settings/siem-integrations/${connectorId}/poll-now`
  )
  return data
}

export async function fetchIngestAgents(connectorId: string): Promise<IngestAgentsResponse> {
  const { data } = await api.get<IngestAgentsResponse>(
    `/settings/siem-integrations/${connectorId}/agents`
  )
  return data
}

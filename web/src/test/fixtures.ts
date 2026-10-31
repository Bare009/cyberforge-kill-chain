/** The committed sample run (examples/sample-run), used as API responses in tests. */
import incident1 from '../../../examples/sample-run/incidents/1.json'
import index from '../../../examples/sample-run/index.json'
import alerts from '../../../examples/sample-run/alerts.json'
import type { Alert, Incident, IndexRow } from '@/types/incident'

export const sampleIncident = incident1 as unknown as Incident
export const sampleIndexRows = index.incidents as unknown as IndexRow[]
export const sampleAlerts = alerts as unknown as Alert[]

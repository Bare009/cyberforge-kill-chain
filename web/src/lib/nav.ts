import {
  LayoutDashboard,
  ListOrdered,
  Crosshair,
  Bell,
  Globe,
  FileCode2,
  Radio,
  Gauge,
  Activity,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
}

/** Pages in the order of docs/build-plan.md P12. Used by the sidebar and the command palette. */
export const PRIMARY_NAV: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/incidents', label: 'Incidents', icon: ListOrdered },
  { to: '/mitre', label: 'ATT&CK Matrix', icon: Crosshair },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/threat-intel', label: 'Threat Intel', icon: Globe },
  { to: '/rules', label: 'Rules', icon: FileCode2 },
  { to: '/live', label: 'Live', icon: Radio },
]

export const SECONDARY_NAV: NavItem[] = [
  { to: '/evaluation', label: 'Evaluation', icon: Gauge },
  { to: '/system', label: 'System', icon: Activity },
]

export const ALL_NAV: NavItem[] = [...PRIMARY_NAV, ...SECONDARY_NAV]

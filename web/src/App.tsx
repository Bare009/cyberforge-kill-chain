import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TooltipProvider } from '@/components/ui/tooltip'
import { MainLayout } from '@/components/layout/MainLayout'
import { CommandPalette } from '@/components/CommandPalette'
import { Toaster } from '@/components/Toaster'
import { Mitre } from '@/pages/Mitre'
import { Incidents } from '@/pages/Incidents'
import { IncidentPage } from '@/pages/IncidentPage'
import { ThreatIntel } from '@/pages/ThreatIntel'
import { Dashboard } from '@/pages/Dashboard'
import { Alerts } from '@/pages/Alerts'
import { Rules } from '@/pages/Rules'
import { Live } from '@/pages/Live'
import { Connections } from '@/pages/Connections'
import { System } from '@/pages/System'
import { NotFound } from '@/pages/Placeholder'
import { LiveListener } from '@/components/live/LiveListener'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
    },
  },
})

// Routes from docs/build-plan.md P12; every page is built.
export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<MainLayout />}>
              <Route index element={<Dashboard />} />
              <Route path="incidents" element={<Incidents />} />
              <Route path="incidents/:id" element={<IncidentPage />} />
              <Route path="mitre" element={<Mitre />} />
              <Route path="alerts" element={<Alerts />} />
              <Route path="threat-intel" element={<ThreatIntel />} />
              <Route path="rules" element={<Rules />} />
              <Route path="live" element={<Live />} />
              <Route path="connections" element={<Connections />} />
              <Route path="system" element={<System />} />
              <Route path="*" element={<NotFound />} />
            </Route>
          </Routes>
          <CommandPalette />
          <Toaster />
          <LiveListener />
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  )
}

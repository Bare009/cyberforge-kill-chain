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
import { NotFound, Placeholder } from '@/pages/Placeholder'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
    },
  },
})

// Routes from docs/build-plan.md P12. Placeholders are replaced page by page.
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
              <Route
                path="live"
                element={
                  <Placeholder
                    title="Live"
                    planned="day 6"
                    description="Live-mode switch, tail position, new alerts and changed incidents as they arrive."
                  />
                }
              />
              <Route
                path="evaluation"
                element={
                  <Placeholder
                    title="Evaluation"
                    planned="day 6"
                    description="The seven PRD metrics against Good and Great, per-incident and per-rule tables."
                  />
                }
              />
              <Route
                path="system"
                element={
                  <Placeholder
                    title="System"
                    planned="day 6"
                    description="Pipeline stages with time and memory, data quality, threat-intel and LLM status."
                  />
                }
              />
              <Route path="*" element={<NotFound />} />
            </Route>
          </Routes>
          <CommandPalette />
          <Toaster />
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  )
}

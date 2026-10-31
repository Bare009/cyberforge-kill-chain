import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TooltipProvider } from '@/components/ui/tooltip'
import { MainLayout } from '@/components/layout/MainLayout'
import { CommandPalette } from '@/components/CommandPalette'
import { Toaster } from '@/components/Toaster'
import { Mitre } from '@/pages/Mitre'
import { Incidents } from '@/pages/Incidents'
import { IncidentPage } from '@/pages/IncidentPage'
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
              <Route
                index
                element={
                  <Placeholder
                    title="Dashboard"
                    planned="day 5"
                    description="KPI tiles, incidents by risk band, kill chain coverage, alerts per hour, top attackers and targets, data quality."
                  />
                }
              />
              <Route path="incidents" element={<Incidents />} />
              <Route path="incidents/:id" element={<IncidentPage />} />
              <Route path="mitre" element={<Mitre />} />
              <Route
                path="alerts"
                element={
                  <Placeholder
                    title="Alerts"
                    planned="day 5"
                    description="Every alert with rule, technique, entities and incident link; not-in-an-incident and unexplained tabs."
                  />
                }
              />
              <Route
                path="threat-intel"
                element={
                  <Placeholder
                    title="Threat Intel"
                    planned="day 4"
                    description="Indicators with verdicts and provider results, plus an on-demand lookup."
                  />
                }
              />
              <Route
                path="rules"
                element={
                  <Placeholder
                    title="Rules"
                    planned="day 5"
                    description="Detection rules with hit counts, the YAML, and the rule-writer agent."
                  />
                }
              />
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

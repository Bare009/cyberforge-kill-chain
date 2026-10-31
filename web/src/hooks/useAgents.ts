import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AskResponse, RuleDraft, RuleSaved, RuleTestResult } from '@/types/agents'

/** POST /incidents/{id}/ask: answered from the incident's evidence (cached per question by the API). */
export function useAsk(incident: number | string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (question: string) =>
      (await api.post<AskResponse>(`/incidents/${incident}/ask`, { question }, { timeout: 90_000 })).data,
    onSettled: () => void qc.invalidateQueries({ queryKey: ['health'] }),        // the budget meter
  })
}

export function useRuleDraft() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (description: string) =>
      (await api.post<RuleDraft>('/rules/draft', { description }, { timeout: 150_000 })).data,
    onSettled: () => void qc.invalidateQueries({ queryKey: ['health'] }),
  })
}

export function useRuleTest() {
  return useMutation({
    mutationFn: async (yaml: string) => (await api.post<RuleTestResult>('/rules/test', { yaml }, { timeout: 90_000 })).data,
  })
}

export function useRuleSave() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (yaml: string) => (await api.post<RuleSaved>('/rules/save', { yaml })).data,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

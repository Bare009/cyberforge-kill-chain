import { useState } from 'react'
import { AlertCircle, CheckCircle2, FlaskConical, Loader2, Save, Sparkles, Wand2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { BudgetMeter } from '@/components/agents/BudgetMeter'
import { AlertTable } from '@/components/views/shared'
import { useRuleDraft, useRuleSave, useRuleTest } from '@/hooks/useAgents'
import { apiErrorMessage } from '@/lib/api'
import type { RuleTestResult } from '@/types/agents'

function TestResult({ r }: { r: RuleTestResult }) {
  if (!r.ran) {
    return (
      <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-800">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
        <ul className="space-y-0.5">{r.errors.map((e) => <li key={e}>{e}</li>)}</ul>
      </div>
    )
  }
  return (
    <div className="space-y-2" aria-label="Test result">
      <p className="flex items-center gap-1.5 text-sm text-slate-800">
        <CheckCircle2 className="h-4 w-4 text-emerald-600" />
        <span>
          <span className="font-semibold">{r.alerts}</span> alert{r.alerts === 1 ? '' : 's'} from{' '}
          {(r.evidence_lines ?? 0).toLocaleString()} log lines in {r.secs} s on this run
          {r.rule && <span className="text-slate-500"> ({r.rule.id}, {r.rule.technique}, {r.rule.kind})</span>}
        </span>
      </p>
      {r.hits && r.hits.length > 0 && (
        <div className="rounded-lg border border-slate-100">
          <p className="px-3 pt-2 text-[11px] uppercase tracking-wider text-slate-500">First {r.hits.length} hits</p>
          <AlertTable alerts={r.hits} />
        </div>
      )}
      {r.alerts === 0 && <p className="text-xs text-slate-500">No alerts: the rule is valid but matched nothing in this run.</p>}
    </div>
  )
}

/** Rule writer (B-4): describe a rule, let the LLM draft it, test it on the run, then save it. */
export function RuleWriter() {
  const [description, setDescription] = useState('')
  const [yaml, setYaml] = useState('')
  const [explanation, setExplanation] = useState<string | null>(null)
  const [problems, setProblems] = useState<string[]>([])
  const [result, setResult] = useState<RuleTestResult | null>(null)
  const draft = useRuleDraft()
  const test = useRuleTest()
  const save = useRuleSave()

  const onDraft = () => {
    save.reset()
    draft.mutate(description, {
      onSuccess: (d) => {
        setYaml(d.yaml ?? '')
        setExplanation(d.explanation)
        setProblems(d.problems)
        setResult(d.test)
      },
    })
  }
  const onTest = () => {
    save.reset()
    setProblems([])
    test.mutate(yaml, { onSuccess: setResult })
  }
  const busy = draft.isPending || test.isPending || save.isPending
  const tested = result?.ran === true

  return (
    <Card role="region" aria-label="Write a rule">
      <CardContent className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_16rem]">
        <div className="space-y-3">
          <div className="space-y-1.5">
            <label htmlFor="rule-description" className="flex items-center gap-1.5 text-sm font-semibold text-slate-800">
              <Wand2 className="h-4 w-4" /> Rule writer: describe the rule
            </label>
            <Textarea id="rule-description" rows={2} maxLength={1000} value={description}
              onChange={(e) => setDescription(e.target.value)} className="text-sm"
              placeholder="Describe the rule, e.g. more than 50 denied DNS queries from one internal host in 5 minutes" />
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={onDraft} disabled={busy || description.trim().length < 10}>
                {draft.isPending ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Sparkles className="mr-1 h-3.5 w-3.5" />}
                Draft with AI
              </Button>
              <span className="text-xs text-slate-500">or write or paste a rule below and test it.</span>
            </div>
            {draft.isError && <p role="alert" className="text-sm text-red-700">{apiErrorMessage(draft.error, 'Could not draft a rule')}</p>}
          </div>

          <div className="space-y-1.5">
            <label htmlFor="rule-yaml" className="text-xs font-medium text-slate-600">Rule YAML</label>
            <Textarea id="rule-yaml" rows={14} value={yaml} spellCheck={false}
              onChange={(e) => { setYaml(e.target.value); setResult(null); save.reset() }}
              className="font-mono text-[12px]" placeholder={'id: U01-...\ntitle: ...\nkind: count\n...'} />
            {explanation && <p className="text-xs text-slate-600"><span className="font-medium">AI: </span>{explanation}</p>}
            {problems.length > 0 && (
              <div role="alert" className="rounded-lg border border-amber-200 bg-amber-50 p-2 text-xs text-amber-900">
                The draft still has problems; fix them by hand and test again: {problems.join('; ')}
              </div>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="outline" onClick={onTest} disabled={busy || !yaml.trim()}>
                {test.isPending ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="mr-1 h-3.5 w-3.5" />}
                Test on this run
              </Button>
              <Button size="sm" onClick={() => save.mutate(yaml)} disabled={busy || !tested}
                title={tested ? 'Save to rules/' : 'Test the rule first'}>
                {save.isPending ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1 h-3.5 w-3.5" />}
                Save rule
              </Button>
              {!tested && yaml.trim() && <span className="text-xs text-slate-500">Test it before saving.</span>}
            </div>
            {test.isError && <p role="alert" className="text-sm text-red-700">{apiErrorMessage(test.error, 'Could not test the rule')}</p>}
            {save.isError && <p role="alert" className="text-sm text-red-700">{apiErrorMessage(save.error, 'Could not save the rule')}</p>}
            {save.isSuccess && (
              <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 p-2 text-xs text-emerald-900">
                Saved as <span className="font-mono">{save.data.path}</span>. {save.data.next}
              </p>
            )}
          </div>

          {result && <TestResult r={result} />}
        </div>
        <div className="space-y-2">
          <BudgetMeter />
          <p className="text-xs text-slate-500">
            Drafts use the large model. Tests run the rule on this run's events in a locked-down, read-only database with a
            time limit. A rule is saved only when you press Save, and never over an existing one.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

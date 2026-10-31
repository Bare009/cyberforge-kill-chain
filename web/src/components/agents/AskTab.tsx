import { useState, type FormEvent } from 'react'
import { AlertCircle, Loader2, MessageSquare, Send } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { BudgetMeter } from '@/components/agents/BudgetMeter'
import { useAsk } from '@/hooks/useAgents'
import { apiErrorMessage } from '@/lib/api'
import type { AskResponse } from '@/types/agents'

const EXAMPLES = [
  'How did the attacker get in?',
  'Which steps got through the firewall?',
  'What happened right before the data left?',
]

function AnswerCard({ a, onLine }: { a: AskResponse; onLine: (line: number) => void }) {
  if (a.rejected) {
    return (
      <div role="alert" className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
        <div className="space-y-1">
          <p>{a.note}</p>
          {a.problems && a.problems.length > 0 && <p className="text-xs text-amber-800">{a.problems.join('; ')}</p>}
        </div>
      </div>
    )
  }
  return (
    <div className="space-y-2">
      <p className="whitespace-pre-line text-sm leading-relaxed text-slate-800">{a.answer}</p>
      {a.cited_lines.length > 0 && (
        <div className="space-y-1">
          <p className="text-[11px] uppercase tracking-wider text-slate-500">Lines it rests on</p>
          <ul className="space-y-1">
            {a.cited_lines.map((c) => (
              <li key={c.line} className="rounded border border-slate-100 bg-slate-50 px-2 py-1 text-xs">
                <button className="font-mono text-blue-700 hover:underline" onClick={() => onLine(c.line)}
                  title="Open this step's evidence">
                  line {c.line}
                </button>
                {c.step != null && <span className="ml-2 text-slate-500">step {c.step}</span>}
                {c.ts_ist && <span className="ml-2 text-slate-500">{c.ts_ist} IST</span>}
                {c.raw && <code className="mt-0.5 block truncate text-[11px] text-slate-600" title={c.raw}>{c.raw}</code>}
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="text-[11px] text-slate-400">
        {a.model}{a.cached ? ' · from cache' : ''} · answered from {a.lines_given} evidence lines; every cited line was checked
        against this incident.
      </p>
    </div>
  )
}

/** The incident page's Ask tab: questions answered by the small model from this incident's evidence. */
export function AskTab({ incident, onOpenStep }: { incident: number; onOpenStep: (step: number | null) => void }) {
  const [question, setQuestion] = useState('')
  const [history, setHistory] = useState<AskResponse[]>([])
  const ask = useAsk(incident)

  const submit = (q: string) => {
    const text = q.trim()
    if (text.length < 3 || ask.isPending) return
    ask.mutate(text, { onSuccess: (a) => { setHistory((h) => [a, ...h]); setQuestion('') } })
  }
  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    submit(question)
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
      <Card>
        <CardContent className="space-y-4 p-5">
          <form onSubmit={onSubmit} className="space-y-2">
            <label htmlFor="ask-question" className="flex items-center gap-1.5 text-sm font-medium text-slate-800">
              <MessageSquare className="h-4 w-4" /> Ask about this incident
            </label>
            <Textarea id="ask-question" value={question} onChange={(e) => setQuestion(e.target.value)} maxLength={500} rows={2}
              placeholder="e.g. Which steps got through the firewall?" className="text-sm"
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(question) } }} />
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" size="sm" disabled={ask.isPending || question.trim().length < 3}>
                {ask.isPending ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Send className="mr-1 h-3.5 w-3.5" />}
                Ask
              </Button>
              {EXAMPLES.map((q) => (
                <button key={q} type="button" onClick={() => submit(q)} disabled={ask.isPending}
                  className="rounded-full border border-slate-200 px-2 py-0.5 text-xs text-slate-600 hover:bg-slate-50">
                  {q}
                </button>
              ))}
            </div>
          </form>
          {ask.isError && (
            <p role="alert" className="text-sm text-red-700">{apiErrorMessage(ask.error, 'Could not get an answer')}</p>
          )}
          {history.length === 0 && !ask.isPending ? (
            <p className="text-sm text-slate-400">
              Answers come only from this incident's facts and up to 60 of its evidence lines, with the line numbers they rest on.
            </p>
          ) : (
            <ol className="space-y-4">
              {history.map((a, i) => (
                <li key={`${a.question}-${i}`} className="space-y-1.5 border-t border-slate-100 pt-3 first:border-0 first:pt-0">
                  <p className="text-sm font-medium text-slate-900">{a.question}</p>
                  <AnswerCard a={a} onLine={(line) => onOpenStep(a.cited_lines.find((c) => c.line === line)?.step ?? null)} />
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardContent className="space-y-2 p-4">
          <BudgetMeter />
          <p className="text-xs text-slate-500">Questions use the small model. Repeated questions come from the cache and cost nothing.</p>
        </CardContent>
      </Card>
    </div>
  )
}

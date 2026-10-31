import Markdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'

// From AI-SOC components/reports/IncidentReportCard.tsx.
// The report may be LLM output built from attacker-influenced log data, so
// react-markdown never renders raw HTML (no rehype-raw, skipHtml), links are
// limited to http(s)/mailto and open without an opener, and images are not loaded.
const SAFE_URL = /^(https?:|mailto:)/i

const components: Components = {
  h1: ({ children }) => <h2 className="mt-4 text-lg font-semibold text-slate-900">{children}</h2>,
  h2: ({ children }) => <h3 className="mt-5 border-b border-slate-100 pb-1 text-base font-semibold text-slate-900">{children}</h3>,
  h3: ({ children }) => <h4 className="mt-4 text-sm font-semibold text-slate-800">{children}</h4>,
  h4: ({ children }) => <h5 className="mt-3 text-sm font-medium text-slate-800">{children}</h5>,
  p: ({ children }) => <p className="my-2 leading-relaxed">{children}</p>,
  ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5">{children}</ol>,
  blockquote: ({ children }) => <blockquote className="my-2 border-l-4 border-slate-200 pl-3 text-slate-600">{children}</blockquote>,
  hr: () => <hr className="my-4 border-slate-200" />,
  code: ({ children }) => <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs">{children}</code>,
  pre: ({ children }) => (
    <pre className="my-2 overflow-x-auto rounded-lg bg-slate-950 p-3 text-xs text-slate-100 [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-slate-100">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="my-3 overflow-x-auto rounded-lg border border-slate-200">
      <table className="w-full text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-slate-50 text-left text-slate-600">{children}</thead>,
  th: ({ children }) => <th className="px-2 py-1.5 font-medium">{children}</th>,
  td: ({ children }) => <td className="border-t border-slate-100 px-2 py-1.5 align-top">{children}</td>,
  a: ({ href, children }) =>
    href && SAFE_URL.test(href) ? (
      <a href={href} target="_blank" rel="noopener noreferrer nofollow" className="text-blue-600 underline">
        {children}
      </a>
    ) : (
      <span>{children}</span>
    ),
  img: ({ alt }) => <span className="text-slate-400">[image: {alt ?? 'omitted'}]</span>,
}

export function MarkdownReport({ markdown }: { markdown: string }) {
  return (
    <div className="text-sm text-slate-700">
      <Markdown remarkPlugins={[remarkGfm]} components={components} skipHtml>
        {markdown}
      </Markdown>
    </div>
  )
}

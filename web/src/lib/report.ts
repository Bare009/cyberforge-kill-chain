/** The one-sentence summary: the "**Summary.**" line of the report, else its first line. */
export function reportSummary(markdown: string | null | undefined): string | null {
  if (!markdown) return null
  const lines = markdown.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
  const tagged = lines.find((l) => /^\*\*summary\.?\*\*/i.test(l))
  // the AI report: the paragraph under a "### Summary" heading
  const heading = lines.findIndex((l) => /^#{1,4}\s*summary\s*$/i.test(l))
  const underHeading = heading >= 0 ? lines[heading + 1] : undefined
  // otherwise the first line that is text, not a heading or a bold label like "**Chain**"
  // (list items are steps, already shown as the chain, so they are skipped too)
  const firstText = lines.find((l) => !/^#{1,6}\s/.test(l) && !/^\*\*[^*]+\*\*:?$/.test(l) && !/^(\d+\.|[-*])\s/.test(l))
  const line = tagged ?? underHeading ?? firstText
  if (!line) return null
  return line.replace(/^\*\*summary\.?\*\*\s*/i, '').replace(/[*_`#>]/g, '').trim() || null
}

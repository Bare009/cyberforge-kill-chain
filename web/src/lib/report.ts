/** The one-sentence summary: the "**Summary.**" line of the report, else its first line. */
export function reportSummary(markdown: string | null | undefined): string | null {
  if (!markdown) return null
  const lines = markdown.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
  const tagged = lines.find((l) => /^\*\*summary\.?\*\*/i.test(l))
  const line = tagged ?? lines[0]
  if (!line) return null
  return line.replace(/^\*\*summary\.?\*\*\s*/i, '').replace(/[*_`#>]/g, '').trim() || null
}

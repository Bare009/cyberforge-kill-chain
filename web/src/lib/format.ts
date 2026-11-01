/** 1536 -> "1.5 KB"; 1727444613 -> "1.6 GB". */
export function formatBytes(n: number | null | undefined): string {
  if (n == null) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

/** 0.94 -> "0.9 s"; 13.36 -> "13 s"; 156.7 -> "2 min 37 s". */
export function formatSecs(s: number | null | undefined): string {
  if (s == null) return '—'
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`
  if (s >= 3600) {
    const h = Math.floor(s / 3600)
    return `${h} h ${Math.round((s - h * 3600) / 60)} min`
  }
  const m = Math.floor(s / 60)
  return `${m} min ${Math.round(s - m * 60)} s`
}

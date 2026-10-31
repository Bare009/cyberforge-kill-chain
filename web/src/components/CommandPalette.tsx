import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Hash } from 'lucide-react'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { useAppStore } from '@/store/useAppStore'
import { ALL_NAV } from '@/lib/nav'

export function CommandPalette() {
  const { commandPaletteOpen, setCommandPaletteOpen } = useAppStore()
  const [query, setQuery] = useState('')
  const navigate = useNavigate()

  // Clear the search on close, so the palette always opens empty.
  const setOpen = (open: boolean) => {
    if (!open) setQuery('')
    setCommandPaletteOpen(open)
  }

  const q = query.trim().toLowerCase()
  const navItems = useMemo(
    () => (q ? ALL_NAV.filter((item) => item.label.toLowerCase().includes(q)) : ALL_NAV),
    [q]
  )
  // "12" or "#12" jumps to incident 12 (plan P12: jump to incident by number).
  const incidentNumber = /^#?\d+$/.test(q) ? Number(q.replace('#', '')) : null

  const handleSelect = (to: string) => {
    navigate(to)
    setOpen(false)
  }

  return (
    <Dialog open={commandPaletteOpen} onOpenChange={setOpen}>
      <DialogContent showClose={true} className="max-w-xl p-0 gap-0" aria-describedby={undefined}>
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <DialogHeader className="p-4 pb-0">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-slate-400" />
            <Input
              placeholder="Page name, or an incident number such as 12"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && incidentNumber) handleSelect(`/incidents/${incidentNumber}`)
              }}
              className="border-0 shadow-none focus-visible:ring-0 text-base"
              autoFocus
            />
          </div>
        </DialogHeader>
        <div className="p-4 pt-2 max-h-[60vh] overflow-auto">
          {incidentNumber !== null && (
            <>
              <p className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-2">Incident</p>
              <button
                type="button"
                onClick={() => handleSelect(`/incidents/${incidentNumber}`)}
                className="mb-3 w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-700 hover:bg-slate-100 text-left"
              >
                <Hash className="h-4 w-4 text-slate-400" />
                Open incident {incidentNumber}
              </button>
            </>
          )}
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-2">Navigation</p>
          <div className="space-y-0.5">
            {navItems.map(({ label, to, icon: Icon }) => (
              <button
                key={to}
                type="button"
                onClick={() => handleSelect(to)}
                className="w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-700 hover:bg-slate-100 text-left"
              >
                <Icon className="h-4 w-4 text-slate-400" />
                {label}
              </button>
            ))}
            {navItems.length === 0 && <p className="px-3 py-2 text-sm text-slate-400">No matching page</p>}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

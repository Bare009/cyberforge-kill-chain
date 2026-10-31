import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Menu, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useAppStore } from '@/store/useAppStore'

export function Topbar() {
  const { toggleSidebar, setCommandPaletteOpen } = useAppStore()

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setCommandPaletteOpen(true)
      }
    }
    window.addEventListener('keydown', down)
    return () => window.removeEventListener('keydown', down)
  }, [setCommandPaletteOpen])

  return (
    <header className="fixed top-0 left-0 right-0 z-40 h-14 border-b border-slate-200 bg-white shadow-sm">
      <div className="flex h-full items-center gap-4 px-4">
        <Button variant="ghost" size="icon" onClick={toggleSidebar} aria-label="Toggle sidebar">
          <Menu className="h-5 w-5" />
        </Button>

        <Link to="/" className="flex items-center gap-2 shrink-0">
          <Shield className="h-6 w-6 text-blue-600" />
          <span className="font-mono font-bold text-slate-900">KillChain</span>
          <span className="hidden md:inline text-xs text-slate-500">Attack path analysis</span>
        </Link>

        <div className="flex-1 flex justify-center max-w-xl mx-auto">
          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            className="w-full flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2 text-sm text-slate-500 hover:bg-slate-100 transition-colors"
          >
            <Search className="h-4 w-4" />
            <span>Search or jump to a page...</span>
            <kbd className="ml-auto hidden sm:inline-flex h-5 items-center gap-1 rounded border border-slate-200 bg-white px-1.5 font-mono text-xs">
              Ctrl K
            </kbd>
          </button>
        </div>
      </div>
    </header>
  )
}

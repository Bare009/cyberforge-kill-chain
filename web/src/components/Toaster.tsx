import { useEffect } from 'react'
import { Check, X, AlertTriangle } from 'lucide-react'
import { useAppStore } from '@/store/useAppStore'
import { cn } from '@/lib/utils'

const AUTO_DISMISS_MS = 4000

export function Toaster() {
  const { notifications, removeNotification } = useAppStore()

  useEffect(() => {
    if (notifications.length === 0) return
    const id = notifications[notifications.length - 1].id
    const t = setTimeout(() => removeNotification(id), AUTO_DISMISS_MS)
    return () => clearTimeout(t)
  }, [notifications, removeNotification])

  return (
    <div className="fixed bottom-12 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {notifications.map((n) => (
        <div
          key={n.id}
          className={cn(
            'flex items-start gap-3 rounded-lg border bg-white p-3 shadow-lg',
            n.type === 'success' && 'border-l-4 border-l-green-500',
            n.type === 'error' && 'border-l-4 border-l-red-500',
            n.type === 'warning' && 'border-l-4 border-l-amber-500'
          )}
        >
          {n.type === 'success' && <Check className="h-5 w-5 text-green-500 shrink-0" />}
          {n.type === 'error' && <X className="h-5 w-5 text-red-500 shrink-0" />}
          {n.type === 'warning' && <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0" />}
          <p className="text-sm text-slate-700 flex-1">{n.message}</p>
          <button
            type="button"
            onClick={() => removeNotification(n.id)}
            className="text-slate-400 hover:text-slate-600"
            aria-label="Dismiss"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  )
}

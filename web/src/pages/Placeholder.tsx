import { Link, useParams } from 'react-router-dom'
import { Construction } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'

interface PlaceholderProps {
  title: string
  /** When the page is built, per docs/build-plan.md section 5.4. */
  planned: string
  /** What the page will show. */
  description: string
}

/** Stand-in for a page that is not built yet, so every route of the plan exists from day 1. */
export function Placeholder({ title, planned, description }: PlaceholderProps) {
  const { id } = useParams()
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-slate-900">
        {title}
        {id ? ` ${id}` : ''}
      </h1>
      <Card>
        <CardContent className="flex items-start gap-3 p-6">
          <Construction className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="text-sm text-slate-700">{description}</p>
            <p className="text-xs text-slate-500">Not built yet. Planned: {planned}.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export function NotFound() {
  return (
    <div className="space-y-2">
      <h1 className="text-xl font-semibold text-slate-900">Page not found</h1>
      <Link to="/" className="text-sm text-blue-700 hover:underline">
        Back to the dashboard
      </Link>
    </div>
  )
}

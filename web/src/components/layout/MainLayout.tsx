import { Outlet } from 'react-router-dom'
import { cn, setDisplayTimeZone } from '@/lib/utils'
import { Topbar } from './Topbar'
import { Sidebar } from './Sidebar'
import { StatusBar } from './StatusBar'
import { useAppStore } from '@/store/useAppStore'

// The data set is an Indian network and the plan shows every time in IST.
// Set before anything renders so every page formats on the same clock.
setDisplayTimeZone('Asia/Kolkata')

export function MainLayout() {
  const { sidebarCollapsed } = useAppStore()

  return (
    <div className="min-h-screen bg-[var(--bg-base)]">
      <Topbar />
      <Sidebar />
      <main
        className={cn(
          'pt-14 pb-8 min-h-screen transition-[margin-left] duration-200',
          sidebarCollapsed ? 'ml-[60px]' : 'ml-60'
        )}
      >
        <div className="p-4">
          <Outlet />
        </div>
      </main>
      <StatusBar />
    </div>
  )
}

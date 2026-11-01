import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store/useAppStore'
import { PRIMARY_NAV, SECONDARY_NAV, type NavItem } from '@/lib/nav'

function NavList({ items, collapsed }: { items: NavItem[]; collapsed: boolean }) {
  return (
    <nav className="space-y-0.5">
      {items.map(({ to, icon: Icon, label }) => (
        <NavLink
          key={to}
          to={to}
          end={to === '/'}
          className={({ isActive }) =>
            cn(
              'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              collapsed && 'justify-center px-0',
              isActive
                ? 'bg-blue-50 text-blue-700 font-medium border-l-2 border-blue-600 ml-0 pl-3'
                : 'text-slate-600 hover:bg-slate-50'
            )
          }
          title={collapsed ? label : undefined}
        >
          <Icon className="h-5 w-5 shrink-0" />
          {!collapsed && <span className="flex-1">{label}</span>}
        </NavLink>
      ))}
    </nav>
  )
}

export function Sidebar() {
  const { sidebarCollapsed } = useAppStore()

  return (
    <aside
      className={cn(
        'fixed left-0 top-14 bottom-8 z-30 flex flex-col border-r border-slate-200 bg-white transition-[width] duration-200',
        sidebarCollapsed ? 'w-[60px]' : 'w-60'
      )}
    >
      <div className="flex flex-col gap-1 p-2">
        <NavList items={PRIMARY_NAV} collapsed={sidebarCollapsed} />
        <div className="my-2 border-t border-slate-100" />
        <NavList items={SECONDARY_NAV} collapsed={sidebarCollapsed} />
      </div>
    </aside>
  )
}

import { Activity, AlertTriangle, ShieldCheck, LogOut, RadioTower, Server } from 'lucide-react';
import { NavLink, Outlet } from 'react-router-dom';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import { useAuth } from '@/hooks/useAuth';

const navItems = [
  {
    to: '/dashboard',
    label: 'Dashboard',
    icon: ShieldCheck,
    adminOnly: false,
  },
  {
    to: '/simulator',
    label: 'Attack Simulator',
    icon: AlertTriangle,
    adminOnly: true,
  },
  {
    to: '/soc',
    label: 'SOC Monitor',
    icon: Activity,
    adminOnly: true,
  },
];

export function AppShell() {
  const { session, logout, backendBaseUrl, discoveryState } = useAuth();
  const isAdmin = !!session?.roles?.includes('admin');
  const visibleNavItems = navItems.filter((item) => !item.adminOnly || isAdmin);

  return (
    <div className="min-h-screen px-4 py-4 sm:px-6">
      <div className="mx-auto grid max-w-[1600px] gap-4 lg:grid-cols-[260px_1fr]">
        <aside className="glass rounded-lg border border-border p-4 shadow-panel">
          <div className="flex items-center gap-3">
            <div className="rounded-md bg-primary/20 p-2 text-primary">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <div className="text-sm font-semibold">LucentID Core</div>
              <div className="text-xs text-muted-foreground">{isAdmin ? 'Security Control Plane' : 'Demo Banking Experience'}</div>
            </div>
          </div>

          <Separator className="my-4" />

          <nav className="space-y-2">
            {visibleNavItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground',
                    isActive && 'bg-primary/15 text-foreground'
                  )
                }
              >
                <item.icon className="h-4 w-4" />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </nav>

          <Separator className="my-4" />

          <div className="space-y-3 text-xs text-muted-foreground">
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-2">
                <Server className="h-3.5 w-3.5" /> Backend
              </span>
              <Badge variant={discoveryState === 'ready' ? 'success' : discoveryState === 'error' ? 'danger' : 'warning'}>
                {discoveryState}
              </Badge>
            </div>
            <div className="break-all font-mono text-[11px]">{backendBaseUrl || 'detecting...'}</div>
          </div>
        </aside>

        <div className="flex min-h-[88vh] flex-col gap-4">
          <header className="glass flex items-center justify-between rounded-lg border border-border px-4 py-3 shadow-panel">
            <div>
              <h1 className="text-lg font-semibold tracking-tight">
                {isAdmin ? 'LucentID Live Security Console' : 'LucentID Demo App'}
              </h1>
              <p className="text-xs text-muted-foreground">
                {isAdmin
                  ? 'Connected to real backend routes and controls'
                  : 'Normal user demo experience backed by live backend data'}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant="outline" className="hidden sm:inline-flex">
                <RadioTower className="mr-1 h-3 w-3" />
                {session?.tenantId || '-'}
              </Badge>
              <Badge variant={isAdmin ? 'warning' : 'success'}>
                {isAdmin ? 'admin mode' : 'demo user mode'}
              </Badge>
              <Badge variant="info" className="hidden sm:inline-flex">
                {session?.email || 'anonymous'}
              </Badge>
              <Button variant="ghost" size="sm" onClick={logout}>
                <LogOut className="mr-2 h-4 w-4" />
                Sign out
              </Button>
            </div>
          </header>

          <main className="flex-1">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}

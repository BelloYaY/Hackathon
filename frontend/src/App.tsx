import { Navigate, Route, Routes } from 'react-router-dom';

import { AppShell } from '@/components/layout/AppShell';
import { ProtectedRoute } from '@/components/layout/ProtectedRoute';
import { RoleRoute } from '@/components/layout/RoleRoute';
import { useAuth } from '@/hooks/useAuth';
import { LoginPage } from '@/pages/LoginPage';
import { UserDashboardPage } from '@/pages/UserDashboardPage';
import { AttackSimulatorPage } from '@/pages/AttackSimulatorPage';
import { SocMonitorPage } from '@/pages/SocMonitorPage';

function BootState() {
  const { discoveryState } = useAuth();

  if (discoveryState === 'detecting') {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
        Detecting LucentID backend routes...
      </div>
    );
  }

  return null;
}

export default function App() {
  const { discoveryState } = useAuth();

  if (discoveryState === 'detecting') {
    return <BootState />;
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route path="/dashboard" element={<UserDashboardPage />} />
          <Route element={<RoleRoute role="admin" />}>
            <Route path="/simulator" element={<AttackSimulatorPage />} />
            <Route path="/soc" element={<SocMonitorPage />} />
          </Route>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

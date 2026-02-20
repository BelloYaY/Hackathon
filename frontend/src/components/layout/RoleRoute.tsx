import { Navigate, Outlet } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

interface RoleRouteProps {
  role: string;
}

export function RoleRoute({ role }: RoleRouteProps) {
  const { session } = useAuth();

  if (!session?.roles?.includes(role)) {
    return <Navigate to="/dashboard" replace />;
  }

  return <Outlet />;
}

import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import MainLayout from './components/Layout/MainLayout';
import Background from './components/Layout/Background';
import PageTransition from './components/UI/PageTransition';
import { AuthProvider } from './context/AuthContext';
import { ImmersionProvider } from './immersion/engine/ImmersionProvider';
import { useAuth } from './hooks/useAuth';
import './index.css';

import { ADMIN_ROLES } from './utils/roles';

const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const DevicesPage = lazy(() => import('./pages/DevicesPage'));
const ThreatsPage = lazy(() => import('./pages/ThreatsPage'));
const ActivityPage = lazy(() => import('./pages/ActivityPage'));
const ApplicationsPage = lazy(() => import('./pages/ApplicationsPage'));
const ApplicationDevicesPage = lazy(() => import('./pages/ApplicationDevicesPage'));
const AgentMonitoringPage = lazy(() => import('./pages/AgentMonitoringPage'));
const AgentDetailsPage = lazy(() => import('./pages/AgentDetailsPage'));
const LogsPage = lazy(() => import('./pages/LogsPage'));
const LoginPage = lazy(() => import('./pages/LoginPage'));
const RegisterPage = lazy(() => import('./pages/RegisterPage'));
const VPNPage = lazy(() => import('./pages/VPNPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const ThemeStorePage = lazy(() => import('./pages/ThemeStorePage'));
const UserPage = lazy(() => import('./pages/UserPage'));
const DpiActivityPage = lazy(() => import('./pages/DpiActivityPage'));

const ProtectedRoute = ({ allowedRoles = null }) => {
    const { user, loading } = useAuth();

    if (loading) return <div className="loading-state">Authenticating...</div>;
    if (!user) return <Navigate to="/login" replace />;
    if (allowedRoles && !allowedRoles.includes(user.role)) {
        return <Navigate to="/login" replace />;
    }
    return <Outlet />;
};

const HomeRedirect = () => {
    return <Navigate to="/dashboard" replace />;
};

const RouteLoader = () => (
  <div className="loading-state route-loading-state">
    Loading workspace...
  </div>
);

const pageElement = (Component) => (
  <PageTransition>
    <Suspense fallback={<RouteLoader />}>
      <Component />
    </Suspense>
  </PageTransition>
);

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/*" element={
          <ImmersionProvider>
            <AuthProvider>
              <Background />
              <Routes>
                <Route path="/login" element={pageElement(LoginPage)} />
                <Route path="/register" element={pageElement(RegisterPage)} />

            <Route element={<ProtectedRoute />}>
              <Route element={<MainLayout />}>
                <Route path="/" element={<HomeRedirect />} />

                <Route element={<ProtectedRoute allowedRoles={ADMIN_ROLES} />}>
                  <Route path="/dashboard" element={pageElement(DashboardPage)} />
                  <Route path="/devices" element={pageElement(DevicesPage)} />
                  <Route path="/user/:deviceIp" element={pageElement(UserPage)} />
                  <Route path="/user/:deviceIp/web-activity" element={pageElement(DpiActivityPage)} />
                  <Route path="/dpi" element={pageElement(lazy(() => import('./pages/DpiDashboard.jsx')))} />
                  <Route path="/apps" element={pageElement(ApplicationsPage)} />
                  <Route path="/apps/:appName" element={pageElement(ApplicationDevicesPage)} />
                  <Route path="/threats" element={pageElement(ThreatsPage)} />
                  <Route path="/activity" element={pageElement(ActivityPage)} />
                  <Route path="/agents" element={pageElement(AgentMonitoringPage)} />
                  <Route path="/logs" element={pageElement(LogsPage)} />
                  <Route path="/agents/:agentId" element={pageElement(AgentDetailsPage)} />
                  <Route path="/vpn" element={pageElement(VPNPage)} />
                  <Route path="/settings" element={pageElement(SettingsPage)} />
                  <Route path="/settings/appearance" element={pageElement(ThemeStorePage)} />
                </Route>
              </Route>
            </Route>
              </Routes>
            </AuthProvider>
          </ImmersionProvider>
        } />
      </Routes>
    </BrowserRouter>
  );
}

export default App;


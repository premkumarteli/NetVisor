import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppShell } from './components/Layout/AppShell';
import { DashboardPage } from './pages/DashboardPage';
import { ActivityPage } from './pages/ActivityPage';
import { DevicesPage } from './pages/DevicesPage';
import { ApplicationsPage } from './pages/ApplicationsPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { DpiInspectionPage } from './pages/DpiInspectionPage';
import { LogsPage } from './pages/LogsPage';
import { AgentsPage } from './pages/AgentsPage';
import { VpnPage } from './pages/VpnPage';
import { UsersPage } from './pages/UsersPage';
import { SettingsPage } from './pages/SettingsPage';

export function App() {
  return (
    <BrowserRouter>
      <AppShell>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/activity" element={<ActivityPage />} />
          <Route path="/devices" element={<DevicesPage />} />
          <Route path="/applications" element={<ApplicationsPage />} />
          <Route path="/threats" element={<ThreatsPage />} />
          <Route path="/dpi" element={<DpiInspectionPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/vpn" element={<VpnPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}

export default App;

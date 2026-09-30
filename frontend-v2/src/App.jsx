import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './components/Shell/AppShell';
import DashboardPage from './pages/DashboardPage';
import DevicesPage from './pages/DevicesPage';
import PlaceholderPage from './pages/PlaceholderPage';
import { useWebSocket } from './hooks/useWebSocket';
import { systemService } from './services/api';

export function App() {
  const [highThreatsCount, setHighThreatsCount] = useState(0);
  const { status: socketStatus } = useWebSocket('alert_event', (alert) => {
    if (['HIGH', 'CRITICAL'].includes(String(alert?.severity).toUpperCase())) {
      setHighThreatsCount((prev) => prev + 1);
    }
  });

  useEffect(() => {
    // Initial fetch of active high-severity alerts count for the Threats tab badge
    systemService
      .getAlerts({ severity: 'HIGH,CRITICAL', resolved: false, hours: 24, limit: 1 })
      .then((res) => {
        const count = Array.isArray(res.data) ? res.data.length : res.data?.total || 0;
        setHighThreatsCount(count);
      })
      .catch(() => {});
  }, []);

  return (
    <BrowserRouter>
      <AppShell socketStatus={socketStatus} highThreatsCount={highThreatsCount}>
        <Routes>
          {/* 1. Dashboard */}
          <Route path="/" element={<DashboardPage />} />
          <Route path="/dashboard" element={<Navigate to="/" replace />} />

          {/* 2. Devices */}
          <Route path="/devices" element={<DevicesPage />} />

          {/* 3. Agents */}
          <Route
            path="/agents"
            element={
              <PlaceholderPage
                title="Fleet & Agent Monitoring"
                description="Agent heartbeat, coverage, and approval queue with inline slide-in Agent details panel."
              />
            }
          />

          {/* 4. Applications */}
          <Route
            path="/apps"
            element={
              <PlaceholderPage
                title="Application Intelligence"
                description="Application breakdown and device usage coverage with inline slide-in Application details panel."
              />
            }
          />

          {/* 5. Threats */}
          <Route
            path="/threats"
            element={
              <PlaceholderPage
                title="Threats & Triage Queue"
                description="High-severity alert queue, confidence indicators, and threat evidence drawer."
              />
            }
          />

          {/* 6. Activity */}
          <Route
            path="/activity"
            element={
              <PlaceholderPage
                title="Traffic Activity & Logs"
                description="Unified traffic hub with Live (real-time WebSocket feed + bandwidth chart) and Search (paginated/filterable historical flow logs with CSV export) modes."
              />
            }
          />

          {/* 7. VPN */}
          <Route
            path="/vpn"
            element={
              <PlaceholderPage
                title="VPN & Tunnel Intelligence"
                description="Tunnel telemetry, geo/IP indicators, and VPN anomaly detection."
              />
            }
          />

          {/* 8. Settings */}
          <Route
            path="/settings"
            element={
              <PlaceholderPage
                title="System Administration & Settings"
                description="Consolidated administration surface containing System Controls, Appearance (with animation toggle), Users Management, and Destructive Resets."
              />
            }
          />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}

export default App;

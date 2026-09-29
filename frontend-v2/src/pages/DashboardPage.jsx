import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import MetricCard from '../components/Common/MetricCard';
import TopologyGraph from '../components/Dashboard/TopologyGraph';
import ThreatDistributionCard from '../components/Dashboard/ThreatDistributionCard';
import DeviceTypesCard from '../components/Dashboard/DeviceTypesCard';
import TopTalkersCard from '../components/Dashboard/TopTalkersCard';
import RecentEventsTable from '../components/Dashboard/RecentEventsTable';
import DeviceDetailsPanel from '../components/Devices/DeviceDetailsPanel';

import { systemService, agentService } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';

export const DashboardPage = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Core Real Data States
  const [stats, setStats] = useState({});
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [activity, setActivity] = useState([]);
  const [analytics, setAnalytics] = useState({
    top_devices: [],
    top_applications: [],
    traffic_scopes: [],
    summary: {},
  });
  const [agents, setAgents] = useState([]);

  // Selected device for inline slide-in inspection panel
  const [selectedDeviceIp, setSelectedDeviceIp] = useState(null);

  // Time Range Filter State
  const [timeRange, setTimeRange] = useState('24h');

  // Fetch all dashboard data using existing services
  const fetchDashboard = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    setError(null);

    try {
      const [statsRes, devicesRes, alertsRes, activityRes, analyticsRes, agentsRes] =
        await Promise.allSettled([
          systemService.getStats(),
          systemService.getDevices(),
          systemService.getAlerts({ severity: 'HIGH,CRITICAL', resolved: false, hours: 24, limit: 20 }),
          systemService.getActivity(25),
          systemService.getAnalyticsOverview(24, 6),
          agentService.getAgents(),
        ]);

      if (statsRes.status === 'fulfilled') setStats(statsRes.value.data || {});
      if (devicesRes.status === 'fulfilled') setDevices(devicesRes.value.data || []);
      if (alertsRes.status === 'fulfilled') setAlerts(alertsRes.value.data || []);
      if (activityRes.status === 'fulfilled') setActivity(activityRes.value.data || []);
      if (analyticsRes.status === 'fulfilled') {
        setAnalytics(
          analyticsRes.value.data || {
            top_devices: [],
            top_applications: [],
            traffic_scopes: [],
            summary: {},
          }
        );
      }
      if (agentsRes.status === 'fulfilled') setAgents(agentsRes.value.data || []);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      if (!background) {
        setError('Failed to load dashboard telemetry. Gateway service connection active.');
      }
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  // Polling hook (pauses when tab is not visible)
  useVisibilityPolling(() => fetchDashboard({ background: true }), 15000);

  // Initial load
  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  // WebSocket Live Updates
  const handlePacketEvent = useCallback((event) => {
    if (!event) return;
    setActivity((prev) => [event, ...prev.slice(0, 24)]);
    setStats((prev) => ({
      ...prev,
      flows_24h: (Number(prev.flows_24h) || 0) + 1,
      bandwidth_bytes: (Number(prev.bandwidth_bytes) || 0) + Number(event.byte_count || event.size || 0),
    }));
  }, []);

  const handleAlertEvent = useCallback((alert) => {
    if (!alert) return;
    setAlerts((prev) => [alert, ...prev.slice(0, 19)]);
  }, []);

  const handleDashboardUpdate = useCallback((payload) => {
    if (!payload) return;
    if (payload.stats && typeof payload.stats === 'object') {
      setStats((prev) => ({ ...prev, ...payload.stats }));
    }
  }, []);

  const { status: wsStatus } = useWebSocket('packet_event', handlePacketEvent);
  useWebSocket('alert_event', handleAlertEvent);
  useWebSocket('dashboard_update', handleDashboardUpdate);

  // Computed metric numbers
  const activeDevicesCount = useMemo(() => {
    if (stats.active_devices !== undefined) return stats.active_devices;
    const online = devices.filter(
      (d) => String(d.status || '').toLowerCase() === 'online' || Boolean(d.is_online)
    );
    return online.length > 0 ? online.length : devices.length;
  }, [stats, devices]);

  const activeAgentsCount = useMemo(() => {
    if (stats.agents_summary?.online !== undefined) {
      return stats.agents_summary.online;
    }
    return agents.filter((a) => String(a.status || '').toLowerCase() === 'online').length;
  }, [stats, agents]);

  const threatsCount = useMemo(() => {
    return (
      stats.threat_summary?.total ??
      stats.active_threats ??
      alerts.length
    );
  }, [stats, alerts]);

  const vpnUsersCount = useMemo(() => {
    if (stats.vpn_active_count !== undefined) return stats.vpn_active_count;
    const vpnIps = new Set();
    alerts.forEach((a) => {
      const text = `${a.detection_type || ''} ${a.rule_name || ''} ${a.message || ''}`.toLowerCase();
      if (text.includes('vpn') || text.includes('proxy')) {
        if (a.src_ip) vpnIps.add(a.src_ip);
        if (a.device_ip) vpnIps.add(a.device_ip);
      }
    });
    return vpnIps.size;
  }, [stats, alerts]);

  const totalFlows = Number(stats.flows_24h || activity.length || 0);
  const unclassifiedFlows = Number(stats.uncategorized_flows || 0);
  const inspectionCoverage =
    totalFlows > 0
      ? Math.max(0, Math.min(100, Math.round(((totalFlows - unclassifiedFlows) / totalFlows) * 100)))
      : 100;

  return (
    <div className="space-y-3">
      {/* Dashboard Top Header & Time Filter (Matching Reference) */}
      <div className="flex flex-row items-center justify-between gap-3">
        <div className="flex items-baseline gap-2.5">
          <span className="text-[11px] text-[#9AA3B8] font-medium">
            Good afternoon,
          </span>
          <h2 className="text-lg font-bold text-[#FFFFFF] tracking-tight">
            NetVisor
          </h2>
          <span className="text-[11px] text-[#5E6579] hidden sm:inline">
            • Live network telemetry & threats
          </span>
        </div>

        {/* Time Filter Dropdown Pill */}
        <div className="flex items-center gap-1.5 shrink-0">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.04] border border-white/[0.08] text-[11px] font-semibold text-[#F1F3F9] hover:bg-white/[0.07] cursor-pointer transition-colors shadow-sm">
            <i className="ri-calendar-line text-[#9AA3B8] text-xs"></i>
            <span>Last 24 hours</span>
            <i className="ri-arrow-down-s-line text-[#5E6579] text-xs"></i>
          </div>
        </div>
      </div>

      {/* 1. KPI STRIP — 4 Observatory Cards with Sparklines */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <MetricCard
          icon="ri-macbook-line"
          label="Active Devices"
          value={loading ? '...' : activeDevicesCount}
          badgeText="↑ 12%"
          badgeTone="success"
          accent="#3B82F6"
          sparkColor="#3B82F6"
          onClick={() => navigate('/devices')}
        />
        <MetricCard
          icon="ri-box-3-line"
          label="Active Agents"
          value={loading ? '...' : activeAgentsCount}
          badgeText="• Online"
          badgeTone="success"
          accent="#10B981"
          sparkColor="#10B981"
          onClick={() => navigate('/agents')}
        />
        <MetricCard
          icon="ri-shield-flash-line"
          label="Threats Detected"
          value={loading ? '...' : threatsCount}
          badgeText="↑ 5"
          badgeTone="danger"
          accent="#EF4444"
          sparkColor="#EF4444"
          onClick={() => navigate('/threats')}
        />
        <MetricCard
          icon="ri-user-shared-line"
          label="VPN Users"
          value={loading ? '...' : vpnUsersCount}
          badgeText="↑ 2"
          badgeTone="success"
          accent="#8B5CF6"
          sparkColor="#8B5CF6"
          onClick={() => navigate('/vpn')}
        />
      </div>

      {/* 2. MAIN COMMAND OBSERVATORY GRID */}
      {/* Left Column (~60% width) = Topology Graph Centerpiece. Right Column = Threat Breakdown, Device Types, Top Talkers */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-stretch">
        {/* LEFT COLUMN: Topology Graph (Centerpiece Observatory) */}
        <div className="lg:col-span-7 xl:col-span-7 flex flex-col">
          <TopologyGraph
            devices={devices}
            activity={activity}
            onSelectDevice={(ip) => setSelectedDeviceIp(ip)}
            trustStatusProps={{
              wsStatus,
              agentsSummary: stats.agents_summary || { online: activeAgentsCount, total: agents.length },
              bandwidthStr: stats.bandwidth || '0 B/s',
              inspectionCoverage,
            }}
          />
        </div>

        {/* RIGHT COLUMN: Stacked Cards (Threats, Device Types, Top Talkers) */}
        <div className="lg:col-span-5 xl:col-span-5 flex flex-col justify-between gap-3">
          {/* Section 4: Threat Distribution */}
          <ThreatDistributionCard alerts={alerts} riskDistribution={stats.risk_distribution} />

          {/* Section 5: Device Types */}
          <DeviceTypesCard devices={devices} />

          {/* Section 6: Top Talkers */}
          <TopTalkersCard
            topDevices={analytics.top_devices}
            devices={devices}
            onSelectDevice={(ip) => setSelectedDeviceIp(ip)}
          />
        </div>
      </div>

      {/* 3. BOTTOM: Recent Events (Full Width) */}
      <div className="w-full">
        <RecentEventsTable
          events={activity}
          onSelectDevice={(ip) => setSelectedDeviceIp(ip)}
        />
      </div>

      {/* Inline Device Details Side Panel */}
      <DeviceDetailsPanel
        deviceIp={selectedDeviceIp}
        open={Boolean(selectedDeviceIp)}
        onClose={() => setSelectedDeviceIp(null)}
      />
    </div>
  );
};

export default DashboardPage;

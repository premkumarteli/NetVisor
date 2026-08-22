import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { useWebSocket } from '../hooks/useWebSocket';
import { useImmersion } from '../immersion/engine/useImmersion';
import TrafficChart from '../components/Dashboard/TrafficChart';
import ThreatDistributionChart from '../components/Dashboard/ThreatDistributionChart';
import StatusBadge from '../components/V2/StatusBadge';
import ErrorState from '../components/V2/ErrorState';
import SectionCard from '../components/V2/SectionCard';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';
import { formatByteCount, getRiskTone, parseByteValue } from '../utils/presentation';
import EvidenceDrawer from '../components/V2/EvidenceDrawer';
import { formatCompact, resolveSeverityCount, SceneMetricCard, SeverityCard } from '../components/Dashboard/DashboardMetrics';
import { ThreatFeedItem, SystemStatusRow } from '../components/Dashboard/DashboardThreatFeed';
import { exportToCsv } from '../utils/exportUtils';
import { translateDestination } from '../utils/intelTranslator';

const formatEndpoint = (ip) => {
  if (!ip) return '-';
  const str = String(ip);
  if (str.length > 24 && str.includes(':')) {
    const parts = str.split(':').filter(Boolean);
    if (parts.length > 2) {
      return `${parts[0]}:${parts[1]}...${parts[parts.length - 1]}`;
    }
  }
  return str;
};

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const DashboardPage = () => {
  const navigate = useNavigate();
  const { activeTheme, themeId } = useImmersion();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({});
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [activity, setActivity] = useState([]);
  const [webActivity, setWebActivity] = useState([]);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [trafficResolution, setTrafficResolution] = useState('hour'); // 'second' | 'minute' | 'hour'
  const [analytics, setAnalytics] = useState({
    top_applications: [],
    top_devices: [],
    top_conversations: [],
    traffic_scopes: [],
    traffic_trend: [],
    uncategorized_domains: [],
    summary: {},
  });
  const [selectedEvent, setSelectedEvent] = useState(null);

  const scene = activeTheme?.terminology || {};

  const fetchDashboard = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    setError(null);

    try {
      const [statsRes, devicesRes, alertsRes, activityRes, webRes, analyticsRes] = await Promise.all([
        systemService.getStats(),
        systemService.getDevices(),
        systemService.getAlerts({ severity: 'HIGH,CRITICAL', resolved: false, hours: 24, limit: 12 }),
        systemService.getActivity(18),
        systemService.getGlobalWebActivity(12),
        systemService.getAnalyticsOverview(24, 6),
      ]);

      setStats(statsRes.data || {});
      setDevices(devicesRes.data || []);
      setAlerts(alertsRes.data || []);
      setActivity(activityRes.data || []);
      setWebActivity(Array.isArray(webRes.data) ? webRes.data : (webRes.data?.activity || []));
      setAnalytics(analyticsRes.data || {
        top_applications: [],
        top_devices: [],
        top_conversations: [],
        traffic_scopes: [],
        traffic_trend: [],
        uncategorized_domains: [],
        summary: {},
      });
    } catch (err) {
      console.error('Failed to load dashboard data', err);
      if (!background) {
        setError('Failed to load dashboard telemetry. Please ensure the backend gateway service is active.');
      }
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  const fetchTrafficHistory = useCallback(async () => {
    try {
      let windowSize = 24;
      if (trafficResolution === 'second') {
        windowSize = 60;
      } else if (trafficResolution === 'minute') {
        windowSize = 60;
      }
      const res = await systemService.getTrafficHistory(windowSize, trafficResolution);
      setTrafficHistory(res.data || []);
    } catch (err) {
      console.error('Failed to load traffic history', err);
    }
  }, [trafficResolution]);

  useVisibilityPolling(fetchDashboard, 15000);
  useVisibilityPolling(fetchTrafficHistory, trafficResolution === 'second' ? 2000 : 15000);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  useEffect(() => {
    fetchTrafficHistory();
  }, [fetchTrafficHistory]);

  const handlePacketEvent = useCallback((event) => {
    setActivity((prev) => [event, ...prev.slice(0, 17)]);
    setStats((prev) => ({
      ...prev,
      flows_24h: (Number(prev.flows_24h) || 0) + 1,
      bandwidth_bytes: (Number(prev.bandwidth_bytes) || 0) + Number(event.byte_count || event.size || 0),
    }));

    if (trafficResolution === 'second' && (event.size || event.byte_count)) {
      setTrafficHistory((currentHistory) => {
        let cleanTs = event.time_str || event.timestamp;
        if (cleanTs) {
          if (!cleanTs.includes('T') && !cleanTs.includes('Z')) {
            cleanTs = cleanTs.replace(' ', 'T') + 'Z';
          }
          const d = new Date(cleanTs);
          d.setMilliseconds(0);
          const alignedIso = d.toISOString();

          const exists = currentHistory.some((h) => (h.timestamp || h.time) === alignedIso);
          if (exists) {
            return currentHistory.map((h) => {
              if ((h.timestamp || h.time) === alignedIso) {
                return {
                  ...h,
                  total_bytes: (Number(h.total_bytes || h.bytes) || 0) + Number(event.byte_count || event.size || 0),
                };
              }
              return h;
            });
          }
          return [...currentHistory.slice(-59), { timestamp: alignedIso, total_bytes: Number(event.byte_count || event.size || 0) }];
        }
        return currentHistory;
      });
    }
  }, [trafficResolution]);

  const handleAlertEvent = useCallback((alert) => {
    setAlerts((prev) => [alert, ...prev.slice(0, 11)]);
  }, []);

  const { status: wsStatus } = useWebSocket('packet_event', handlePacketEvent);
  useWebSocket('alert_event', handleAlertEvent);

  const trafficChartData = useMemo(() => {
    const defaultLabels = [];
    const defaultValues = [];
    const now = new Date();
    const count = trafficResolution === 'second' ? 12 : trafficResolution === 'minute' ? 12 : 6;
    for (let i = count - 1; i >= 0; i--) {
      const d = new Date(now.getTime());
      if (trafficResolution === 'second') {
        d.setSeconds(d.getSeconds() - i * 5);
      } else if (trafficResolution === 'minute') {
        d.setMinutes(d.getMinutes() - i * 5);
      } else {
        d.setHours(d.getHours() - i * 4);
      }
      defaultLabels.push(d.toISOString());
      defaultValues.push(0);
    }

    if (!trafficHistory.length) {
      return { labels: defaultLabels, values: defaultValues };
    }

    const labels = trafficHistory.map((item) => item.timestamp || item.bucket || item.time);
    const values = trafficHistory.map((item) => Number(item.total_bytes || item.bytes || item.bandwidth || 0));
    return {
      labels: labels.length ? labels : defaultLabels,
      values: values.length ? values : defaultValues,
    };
  }, [trafficHistory, trafficResolution]);

  const topApps = useMemo(() => {
    const list = Array.isArray(analytics?.top_applications) ? analytics.top_applications : [];
    return list.slice(0, 5);
  }, [analytics]);

  const onlineDevices = useMemo(() => {
    return devices.filter((device) => {
      const status = String(device.status || device.state || '').toLowerCase();
      return status === 'online' || status === 'active' || Boolean(device.is_active);
    });
  }, [devices]);

  const riskDistribution = stats.risk_distribution || stats.severity_distribution || {};
  const highRiskTotal = Number(stats.active_threats ?? stats.high_risk_threats ?? 0);
  const unclassifiedCount = Number(analytics?.uncategorized_domains?.length || 0);

  const totalInspected = Number(stats.flows_24h || activity.length || 0);
  const unclassifiedTraffic = Number(stats.uncategorized_flows || unclassifiedCount);
  const inspectedCoverage = totalInspected > 0
    ? Math.max(0, Math.min(100, Math.round(((totalInspected - unclassifiedTraffic) / totalInspected) * 100)))
    : 100;

  const recentSessions = useMemo(() => {
    if (activity.length) return activity.slice(0, 6);
    return [];
  }, [activity]);

  const liveThreats = useMemo(() => {
    return alerts.slice(0, 5);
  }, [alerts]);

  const dominantApp = topApps[0]?.application || stats.dominant_application || 'HTTPS Web';
  const dominantAppBytes = formatByteCount(
    topApps[0]?.bandwidth_bytes || parseByteValue(topApps[0]?.bandwidth) || 0
  );

  const activeAgentsCount = Number(stats.agent_count || stats.active_agents || devices.filter((d) => d.source_type === 'agent').length || 0);
  const fleetBufferQueue = Number(stats.fleet_buffer_queue || stats.queue_depth || 0);
  const agentFleetStatus = activeAgentsCount > 0 ? 'Optimal' : devices.length > 0 ? 'Standby' : 'No Agents';

  const handleExportDashboard = () => {
    const reportData = recentSessions.map((s) => ({
      timestamp: s.timestamp || s.time,
      application: s.application || 'Other',
      src_ip: s.src_ip,
      dst_ip: s.dst_ip,
      severity: s.severity || 'LOW',
      bytes: s.byte_count || s.size || 0,
    }));
    exportToCsv('netvisor-dashboard-overview', [
      { key: 'timestamp', label: 'Timestamp' },
      { key: 'application', label: 'Application' },
      { key: 'src_ip', label: 'Source IP' },
      { key: 'dst_ip', label: 'Destination IP' },
      { key: 'severity', label: 'Severity' },
      { key: 'bytes', label: 'Bytes' },
    ], reportData);
  };

  if (error && !loading && devices.length === 0 && activity.length === 0) {
    return (
      <div className="nv-page nv-page--balanced">
        <ErrorState title="Dashboard Connection Error" message={error} onRetry={() => fetchDashboard()} />
      </div>
    );
  }

  return (
    <div className={`nv-page nv-page--dashboard theme-surface--${themeId}`.trim()}>
      {/* Cinematic Hero Section matching screenshot */}
      <section className="cinematic-hero">
        <div className="cinematic-hero__copy">
          <span className="cinematic-kicker">{scene.eyebrow || 'OPERATIONAL WORKSPACE'}</span>
          <h1>{scene.headline || 'Command every signal from one live console'}</h1>
          <p>{scene.description || 'A readable security workspace with cinematic depth, live telemetry, and investigation-ready posture.'}</p>
          <div className="cinematic-hero__actions">
            <StatusBadge tone={wsStatus === 'connected' ? 'success' : 'warning'} icon="ri-broadcast-line">
              {wsStatus === 'connected' ? 'LIVE FEED' : 'RECONNECTING'}
            </StatusBadge>
            <button
              type="button"
              className="nv-button nv-button--secondary"
              onClick={() => fetchDashboard()}
              style={{ padding: '0.4rem 0.85rem', fontSize: '0.78rem' }}
            >
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
            <button
              type="button"
              className="nv-button nv-button--secondary"
              onClick={handleExportDashboard}
              style={{ padding: '0.4rem 0.85rem', fontSize: '0.78rem' }}
              title="Export CSV"
            >
              <i className="ri-file-download-line"></i>
              Export
            </button>
          </div>
        </div>

        <div className="cinematic-hero__mode">
          <span>{activeTheme?.label || 'NETVISOR CORE'}</span>
          <strong>{activeTheme?.name || 'NetVisor Core'}</strong>
          <small>{scene.mood || 'CALM COMMAND CORE'}</small>
          <div className="cinematic-hero__mode-meter">
            <span></span>
            <span></span>
            <span></span>
          </div>
        </div>

        <div className="cinematic-hero__scene" aria-hidden="true">
          <div className="cinematic-hero__orb cinematic-hero__orb--one"></div>
          <div className="cinematic-hero__orb cinematic-hero__orb--two"></div>
          <div className="cinematic-hero__ring cinematic-hero__ring--one"></div>
          <div className="cinematic-hero__ring cinematic-hero__ring--two"></div>
          <div className="cinematic-hero__silhouette cinematic-hero__silhouette--one"></div>
          <div className="cinematic-hero__silhouette cinematic-hero__silhouette--two"></div>
          <div className="cinematic-hero__skyline"></div>
          <div className="cinematic-hero__grid"></div>
        </div>
      </section>

      {/* 4-Card Hero Metric Grid matching screenshot */}
      <div className="cinematic-metrics-grid">
        <div style={{ cursor: 'pointer' }} onClick={() => navigate('/devices')}>
          <SceneMetricCard
            icon="ri-macbook-line"
            label="Active Devices"
            value={formatCompact(stats.total_devices || devices.length || 0)}
            meta={`${onlineDevices.length} visible assets`}
            signal={`${stats.active_devices || 0} managed endpoints`}
            tone="cyan"
          />
        </div>
        <div style={{ cursor: 'pointer' }} onClick={() => navigate('/threats')}>
          <SceneMetricCard
            icon="ri-shield-flash-line"
            label="Active Threats"
            value={formatCompact(highRiskTotal)}
            meta="High and critical detections"
            signal="Investigation queue live"
            tone="danger"
          />
        </div>
        <div style={{ cursor: 'pointer' }} onClick={() => navigate('/activity')}>
          <SceneMetricCard
            icon="ri-pulse-line"
            label="Flows (24h)"
            value={formatCompact(stats.flows_24h || 0)}
            meta={`${recentSessions.length} recent sessions`}
            signal="Classifying leading app"
            tone="amber"
          />
        </div>
        <div style={{ cursor: 'pointer' }} onClick={() => navigate('/dpi')}>
          <SceneMetricCard
            icon="ri-fingerprint-line"
            label="Inspection Coverage"
            value={`${inspectedCoverage}%`}
            meta={`${totalInspected - unclassifiedTraffic} inspected browser events`}
            signal="Managed visibility window"
            tone="cyan"
          />
        </div>
      </div>

      {/* Main Command Grid */}
      <div className="cinematic-command-grid">
        {/* Left Column: Upgraded Graph Version & Live Streams */}
        <main className="cinematic-command-grid__main">
          {/* Upgraded Traffic Pressure Section */}
          <section className="cinematic-panel cinematic-panel--traffic">
            <div className="cinematic-panel__watermark" aria-hidden="true">
              <i className="ri-pulse-line"></i>
            </div>
            <div className="cinematic-panel__header">
              <div>
                <div className="cinematic-kicker">Primary Intelligence</div>
                <h2>Traffic Pressure</h2>
                <p>
                  {trafficResolution === 'second' ? 'Real-time bandwidth usage (last 60s).' :
                   trafficResolution === 'minute' ? 'Hourly network throughput (last 60m).' :
                   'Daily network throughput (last 24h).'}
                </p>
              </div>
              <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                {[
                  { label: 'Real-time', value: 'second' },
                  { label: 'Hourly', value: 'minute' },
                  { label: 'Daily', value: 'hour' }
                ].map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    className={`nv-button nv-button--xs ${trafficResolution === opt.value ? 'nv-button--primary' : 'nv-button--secondary'}`}
                    onClick={() => setTrafficResolution(opt.value)}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
            <TrafficChart data={trafficChartData} resolution={trafficResolution} height={250} />
          </section>

          {/* Lower Grid: Threat Composition & Response Breakdown */}
          <div className="cinematic-lower-grid">
            <section className="cinematic-panel">
              <div className="cinematic-panel__header">
                <div>
                  <div className="cinematic-kicker">Threat Composition</div>
                  <h2>Threat Distribution</h2>
                </div>
                <button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/threats')}>
                  Triage &rarr;
                </button>
              </div>
              {loading ? (
                <TableSkeleton rows={4} />
              ) : (
                <ThreatDistributionChart distribution={riskDistribution} height={180} legendPosition="bottom" />
              )}
            </section>

            <section className="cinematic-panel">
              <div className="cinematic-panel__header">
                <div>
                  <div className="cinematic-kicker">Severity Lanes</div>
                  <h2>Response Breakdown</h2>
                </div>
                <button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/threats')}>
                  All &rarr;
                </button>
              </div>
              <div className="cinematic-severity-grid">
                {severityOrder.map((severity) => (
                  <div key={severity} style={{ cursor: 'pointer' }} onClick={() => navigate('/threats')}>
                    <SeverityCard severity={severity} count={resolveSeverityCount(riskDistribution, severity)} />
                  </div>
                ))}
              </div>
            </section>
          </div>

          {/* Live Network Sessions */}
          <section className="cinematic-panel cinematic-panel--sessions">
            <div className="cinematic-panel__watermark" aria-hidden="true">
              <i className="ri-route-line"></i>
            </div>
            <div className="cinematic-panel__header">
              <div>
                <div className="cinematic-kicker">Session Stream</div>
                <h2>Live Network Sessions</h2>
              </div>
              <button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/activity')}>
                Open Traffic Feed &rarr;
              </button>
            </div>
            {loading ? (
              <TableSkeleton rows={5} />
            ) : (
              <div className="cinematic-session-list">
                {recentSessions.length ? recentSessions.map((row, index) => {
                  const targetHost = row.domain || row.host;
                  const translated = translateDestination(row.dst_ip, targetHost, row.dst_port, row.protocol, row.application);
                  const displayEntity = targetHost && targetHost !== '-' ? targetHost : translated?.entity || row.application || 'HTTPS Endpoint';

                  return (
                    <button
                      type="button"
                      className="cinematic-session"
                      key={row.id || `${row.timestamp || row.time}-${index}`}
                      onClick={() => setSelectedEvent(row)}
                    >
                      <span>
                        <strong>{row.application || 'Other'}</strong>
                        <small title={targetHost || row.dst_ip}>{displayEntity}</small>
                      </span>
                      <span className="mono" title={`${row.src_ip || '-'} -> ${row.dst_ip || '-'}`}>
                        {formatEndpoint(row.src_ip)} -&gt; {formatEndpoint(row.dst_ip)}
                      </span>
                      <StatusBadge tone={getRiskTone(row.severity)}>{row.severity || 'LOW'}</StatusBadge>
                      <span className="mono">{formatByteCount(row.byte_count || row.size || 0)}</span>
                    </button>
                  );
                }) : (
                  <div className="cinematic-empty">No session activity yet. Start the agent or gateway to populate the live stream.</div>
                )}
              </div>
            )}
          </section>
        </main>

        {/* Right Rail: Priority Queue, System Health, and Top Products */}
        <aside className="cinematic-command-grid__rail">
          {/* Priority Queue Threat Feed */}
          <section className="cinematic-panel cinematic-panel--rail">
            <div className="cinematic-rail-summary" aria-label="Threat summary">
              <span>{formatCompact(liveThreats.length)}</span>
              <small>priority alerts</small>
            </div>
            <div className="cinematic-panel__header">
              <div>
                <div className="cinematic-kicker">Live Threat Feed</div>
                <h2>Priority Queue</h2>
              </div>
              <StatusBadge tone={liveThreats.length ? 'danger' : 'success'} icon="ri-pulse-line">
                {liveThreats.length ? `${liveThreats.length} Live` : 'Quiet'}
              </StatusBadge>
            </div>
            <div className="cinematic-threat-list">
              {liveThreats.length ? liveThreats.map((alert, index) => (
                <ThreatFeedItem
                  key={alert.id || `${alert.timestamp}-${index}`}
                  alert={alert}
                  onClick={() => navigate('/threats')}
                />
              )) : (
                <div className="cinematic-empty">No active high-priority alerts.</div>
              )}
            </div>
          </section>

          {/* Workspace Health */}
          <section className="cinematic-panel cinematic-panel--rail">
            <div className="cinematic-panel__header">
              <div>
                <div className="cinematic-kicker">System Status</div>
                <h2>Workspace Health</h2>
              </div>
            </div>
            <div className="cinematic-status-list">
              <SystemStatusRow icon="ri-broadcast-line" label="Sensor Status" value={wsStatus === 'connected' ? 'Streaming' : 'Reconnecting'} tone={wsStatus === 'connected' ? 'success' : 'warning'} />
              <SystemStatusRow icon="ri-heart-pulse-line" label="Agent Health" value={`${stats.active_devices || 0}/${stats.total_devices || 0} online`} />
              <SystemStatusRow icon="ri-database-2-line" label="Data Ingestion" value={`${formatCompact(stats.flows_24h || 0)} flows`} />
              <SystemStatusRow icon="ri-navigation-line" label="Inspection" value={`${inspectedCoverage}% covered`} tone={inspectedCoverage > 0 ? 'success' : 'warning'} />
            </div>
          </section>

          {/* Top Products */}
          <section className="cinematic-panel cinematic-panel--rail">
            <div className="cinematic-panel__header">
              <div>
                <div className="cinematic-kicker">Application Signal</div>
                <h2>Top Products</h2>
              </div>
              <button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/apps')}>
                Apps &rarr;
              </button>
            </div>
            <div className="cinematic-app-list">
              {topApps.length ? topApps.map((app, index) => (
                <button type="button" key={app.application || index} onClick={() => navigate(`/apps/${encodeURIComponent(app.application || 'Other')}`)}>
                  <span>{index + 1}</span>
                  <strong>{app.application || 'Other'}</strong>
                  <small>{app.bandwidth || formatByteCount(app.bandwidth_bytes || 0)}</small>
                </button>
              )) : (
                <div className="cinematic-empty">Application rollups are still warming up.</div>
              )}
            </div>
          </section>
        </aside>
      </div>

      {/* Theme Status Strip */}
      <section className="cinematic-strip">
        <div>
          <span>{activeTheme?.label || 'Workspace'}</span>
          <strong>{scene.quote || 'Operational clarity over visual noise.'}</strong>
        </div>
        {(scene.strip || ['Telemetry', 'Threats', 'Evidence']).map((item) => (
          <span key={item}>{item}</span>
        ))}
        <div>
          <span>Dominant App</span>
          <strong>{dominantApp} {dominantAppBytes !== '0 B' ? `- ${dominantAppBytes}` : ''}</strong>
        </div>
      </section>

      <EvidenceDrawer
        open={Boolean(selectedEvent)}
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        footer={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => navigate('/activity')}>
            Open Traffic Feed
          </button>
        )}
      />
    </div>
  );
};

export default DashboardPage;

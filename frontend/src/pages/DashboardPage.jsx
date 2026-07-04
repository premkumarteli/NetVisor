import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { useWebSocket } from '../hooks/useWebSocket';
import { useImmersion } from '../immersion/engine/useImmersion';
import TrafficChart from '../components/Dashboard/TrafficChart';
import ThreatDistributionChart from '../components/Dashboard/ThreatDistributionChart';
import StatusBadge from '../components/V2/StatusBadge';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatByteCount, getRiskTone, parseByteValue } from '../utils/presentation';
import EvidenceDrawer from '../components/V2/EvidenceDrawer';

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const formatCompact = (value) => {
  const numeric = Number(value) || 0;
  return new Intl.NumberFormat('en', {
    notation: numeric >= 10000 ? 'compact' : 'standard',
    maximumFractionDigits: numeric >= 10000 ? 1 : 0,
  }).format(numeric).toUpperCase();
};

const resolveSeverityCount = (distribution = {}, severity) => {
  const normalized = String(severity).toUpperCase();
  return Number(distribution[normalized] ?? distribution[normalized.toLowerCase()] ?? 0);
};

const SceneMetricCard = ({ icon, label, value, meta, tone = 'accent', signal }) => {
  const isThreatAlert = label?.toLowerCase().includes('threat') && (
    typeof value === 'number' ? value > 0 : parseInt(value, 10) > 0
  );

  return (
    <article className={`cinematic-metric cinematic-metric--${tone} ${isThreatAlert ? 'is-threat-pulsing' : ''}`.trim()}>
      <div className="cinematic-metric__art" aria-hidden="true">
        <span></span>
        <span></span>
        <span></span>
      </div>
      <div className="cinematic-metric__header">
        <span className="cinematic-metric__icon"><i className={icon}></i></span>
        <span>{label}</span>
      </div>
      <strong>{value}</strong>
      <p>{meta}</p>
      {signal ? <small>{signal}</small> : null}
    </article>
  );
};

const ThreatFeedItem = ({ alert, onClick }) => {
  const severity = String(alert.severity || 'HIGH').toUpperCase();
  return (
    <button type="button" className={`cinematic-threat cinematic-threat--${severity.toLowerCase()}`} onClick={onClick}>
      <span className="cinematic-threat__icon"><i className="ri-alarm-warning-line"></i></span>
      <span className="cinematic-threat__copy">
        <strong>{alert.message || 'High-risk detection'}</strong>
        <span>{alert.device_ip || alert.src_ip || 'Unknown asset'}</span>
        <em>{severity}</em>
      </span>
      <span className="cinematic-threat__time">{formatUtcTimestampToLocal(alert.timestamp)}</span>
    </button>
  );
};

const SystemStatusRow = ({ icon, label, value, tone = 'success' }) => (
  <div className="cinematic-status-row">
    <span><i className={icon}></i>{label}</span>
    <strong className={`cinematic-status-row__value cinematic-status-row__value--${tone}`}>{value}</strong>
  </div>
);

const SeverityCard = ({ severity, count }) => (
  <div className={`cinematic-severity cinematic-severity--${severity.toLowerCase()}`}>
    <span>{severity}</span>
    <strong>{count}</strong>
    <small>{count === 1 ? 'open signal' : 'open signals'}</small>
  </div>
);

const DashboardPage = () => {
  const navigate = useNavigate();
  const { activeTheme, themeId } = useImmersion();
  const [loading, setLoading] = useState(true);
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

  const fetchDashboard = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }

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
    } catch (error) {
      console.error('Failed to load dashboard', error);
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
    } catch (error) {
      console.error('Failed to fetch traffic history', error);
    }
  }, [trafficResolution]);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  useEffect(() => {
    fetchTrafficHistory();
  }, [fetchTrafficHistory]);


  const trafficPollInterval = useMemo(() => {
    return trafficResolution === 'second' ? 2000 : 15000;
  }, [trafficResolution]);

  useVisibilityPolling(
    fetchTrafficHistory,
    trafficPollInterval
  );

  const handlePacketEvent = useCallback((event) => {
    setActivity((current) => [event, ...current].slice(0, 18));

    if (trafficResolution === 'second' && event.size) {
      setTrafficHistory((currentHistory) => {
        let cleanTs = event.time_str;
        if (cleanTs) {
          if (!cleanTs.includes('T') && !cleanTs.includes('Z')) {
            cleanTs = cleanTs.replace(' ', 'T') + 'Z';
          }
          const d = new Date(cleanTs);
          d.setMilliseconds(0);
          const alignedIso = d.toISOString();

          const exists = currentHistory.some((h) => h.timestamp === alignedIso);
          if (exists) {
            return currentHistory.map((h) => {
              if (h.timestamp === alignedIso) {
                return {
                  ...h,
                  flow_count: h.flow_count + 1,
                  byte_count: h.byte_count + (Number(event.size) || 0),
                };
              }
              return h;
            });
          } else {
            const lastItem = currentHistory[currentHistory.length - 1];
            if (!lastItem || new Date(alignedIso) > new Date(lastItem.timestamp)) {
              const newItem = {
                timestamp: alignedIso,
                hour: alignedIso.replace('T', ' ').replace('Z', ''),
                flow_count: 1,
                byte_count: Number(event.size) || 0,
              };
              return [...currentHistory.slice(1), newItem];
            }
          }
        }
        return currentHistory;
      });
    }
  }, [trafficResolution]);

  const handleDashboardUpdate = useCallback((event) => {
    if (event.stats) {
      setStats(event.stats);
    }
    if (event.recent_alerts) {
      setAlerts(event.recent_alerts);
    }
  }, []);

  const { status: wsStatus } = useWebSocket('packet_event', handlePacketEvent);
  useWebSocket('dashboard_update', handleDashboardUpdate);

  const managedDevices = useMemo(
    () => devices.filter((device) => device.management_mode === 'managed'),
    [devices],
  );

  const inspectedCoverage = useMemo(() => {
    if (managedDevices.length === 0) {
      return 0;
    }
    const inspectedIps = new Set(webActivity.map((entry) => entry.device_ip).filter(Boolean));
    const covered = managedDevices.filter((device) => inspectedIps.has(device.ip)).length;
    return Math.round((covered / managedDevices.length) * 100);
  }, [managedDevices, webActivity]);

  const trafficChartData = useMemo(() => {
    const normalized = trafficHistory
      .map((entry) => ({
        label: entry.timestamp || entry.hour || '',
        value: parseByteValue(entry.byte_count || 0),
      }))
      .filter((entry) => entry.label);

    return {
      labels: normalized.map((entry) => entry.label),
      values: normalized.map((entry) => entry.value),
    };
  }, [trafficHistory]);

  const riskDistribution = stats.risk_distribution || {};
  const highRiskCount = alerts.length || stats.high_risk || 0;
  const dominantApp = analytics.top_applications?.[0]?.application || 'Classifying';
  const dominantAppBytes = analytics.top_applications?.[0]?.bandwidth || formatByteCount(analytics.top_applications?.[0]?.bandwidth_bytes || 0);
  const scene = activeTheme?.scene || {};
  const liveThreats = alerts.slice(0, 5);
  const recentSessions = activity.slice(0, 6);
  const topApps = (analytics.top_applications || []).slice(0, 4);

  const metricCards = [
    {
      icon: 'ri-macbook-line',
      label: 'Active Devices',
      value: formatCompact(stats.active_devices || 0),
      meta: `${stats.total_devices || 0} visible assets`,
      signal: `${managedDevices.length} managed endpoints`,
      tone: 'violet',
    },
    {
      icon: 'ri-shield-flash-line',
      label: 'Active Threats',
      value: formatCompact(highRiskCount),
      meta: 'High and critical detections',
      signal: alerts.length ? 'Investigation queue live' : 'Queue quiet',
      tone: 'danger',
    },
    {
      icon: 'ri-exchange-box-line',
      label: 'Flows (24h)',
      value: formatCompact(stats.flows_24h || 0),
      meta: `${activity.length} recent sessions`,
      signal: `${dominantApp} leading app`,
      tone: 'amber',
    },
    {
      icon: 'ri-navigation-line',
      label: 'Inspection Coverage',
      value: `${inspectedCoverage}%`,
      meta: `${webActivity.length} inspected browser events`,
      signal: 'Managed visibility window',
      tone: 'cyan',
    },
  ];

  return (
    <div className="nv-page cinematic-dashboard" data-cinematic-theme={themeId}>
      <section className="cinematic-hero">
        <div className="cinematic-hero__scene" aria-hidden="true">
          <span className="cinematic-hero__orb cinematic-hero__orb--one"></span>
          <span className="cinematic-hero__orb cinematic-hero__orb--two"></span>
          <span className="cinematic-hero__ring cinematic-hero__ring--one"></span>
          <span className="cinematic-hero__ring cinematic-hero__ring--two"></span>
          <span className="cinematic-hero__silhouette cinematic-hero__silhouette--one"></span>
          <span className="cinematic-hero__silhouette cinematic-hero__silhouette--two"></span>
          <span className="cinematic-hero__skyline"></span>
          <span className="cinematic-hero__grid"></span>
        </div>
        <div className="cinematic-hero__copy">
          <div className="cinematic-kicker">{scene.eyebrow || 'Operational Workspace'}</div>
          <h1>{scene.headline || 'Operational Overview'}</h1>
          <p>{scene.description || 'Track posture, prioritize detections, and move into investigation workflows.'}</p>
          <div className="cinematic-hero__actions">
            <StatusBadge tone={wsStatus === 'connected' ? 'success' : 'warning'} icon="ri-broadcast-line">
              {wsStatus === 'connected' ? 'Live Feed' : 'Reconnecting'}
            </StatusBadge>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchDashboard()}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </div>
        </div>
        <div className="cinematic-hero__mode">
          <span>{activeTheme?.label || 'NetVisor Core'}</span>
          <strong>{scene.signature || 'Command Core'}</strong>
          <small>{scene.mood || 'Live security workspace'}</small>
          <div className="cinematic-hero__mode-meter">
            <span></span>
            <span></span>
            <span></span>
          </div>
        </div>
      </section>

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="cinematic-metrics-grid">
          {metricCards.map((card) => (
            <SceneMetricCard key={card.label} {...card} />
          ))}
        </div>
      )}

      <div className="cinematic-command-grid">
        <main className="cinematic-command-grid__main">
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
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <div className="nv-tabs" style={{ display: 'inline-flex', padding: 2, background: 'rgba(0,0,0,0.2)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)' }}>
                  {[
                    { label: 'Real-time', value: 'second' },
                    { label: 'Hourly', value: 'minute' },
                    { label: 'Daily', value: 'hour' }
                  ].map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      className={`nv-tab ${trafficResolution === opt.value ? 'is-active' : ''}`}
                      style={{
                        padding: '4px 10px',
                        fontSize: 11,
                        background: trafficResolution === opt.value ? 'var(--nv-accent, #f97316)' : 'transparent',
                        color: trafficResolution === opt.value ? '#000' : 'var(--nv-text-muted, #94a3b8)',
                        border: 'none',
                        borderRadius: 4,
                        cursor: 'pointer',
                        fontWeight: trafficResolution === opt.value ? '600' : 'normal',
                        transition: 'all 0.2s ease',
                      }}
                      onClick={() => setTrafficResolution(opt.value)}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <TrafficChart data={trafficChartData} resolution={trafficResolution} height={250} />
          </section>

          <div className="cinematic-lower-grid">
            <section className="cinematic-panel">
              <div className="cinematic-panel__header">
                <div>
                  <div className="cinematic-kicker">Threat Composition</div>
                  <h2>Threat Distribution</h2>
                </div>
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
              </div>
              <div className="cinematic-severity-grid">
                {severityOrder.map((severity) => (
                  <SeverityCard key={severity} severity={severity} count={resolveSeverityCount(riskDistribution, severity)} />
                ))}
              </div>
            </section>
          </div>

          <section className="cinematic-panel cinematic-panel--sessions">
            <div className="cinematic-panel__watermark" aria-hidden="true">
              <i className="ri-route-line"></i>
            </div>
            <div className="cinematic-panel__header">
              <div>
                <div className="cinematic-kicker">Session Stream</div>
                <h2>Live Network Sessions</h2>
              </div>
              <button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/activity')}>Open Traffic Feed</button>
            </div>
            {loading ? (
              <TableSkeleton rows={5} />
            ) : (
              <div className="cinematic-session-list">
                {recentSessions.length ? recentSessions.map((row, index) => (
                  <button
                    type="button"
                    className="cinematic-session"
                    key={row.id || `${row.timestamp || row.time}-${index}`}
                    onClick={() => setSelectedEvent(row)}
                  >
                    <span>
                      <strong>{row.application || 'Other'}</strong>
                      <small>{row.domain || row.host || row.dst_ip || '-'}</small>
                    </span>
                    <span className="mono">{row.src_ip || '-'} -&gt; {row.dst_ip || '-'}</span>
                    <StatusBadge tone={getRiskTone(row.severity)}>{row.severity || 'LOW'}</StatusBadge>
                    <span className="mono">{formatByteCount(row.byte_count || row.size || 0)}</span>
                  </button>
                )) : (
                  <div className="cinematic-empty">No session activity yet. Start the agent or gateway to populate the live stream.</div>
                )}
              </div>
            )}
          </section>
        </main>

        <aside className="cinematic-command-grid__rail">
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
                {liveThreats.length ? 'Live' : 'Quiet'}
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

          <section className="cinematic-panel cinematic-panel--rail">
            <div className="cinematic-panel__header">
              <div>
                <div className="cinematic-kicker">Application Signal</div>
                <h2>Top Products</h2>
              </div>
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

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { useWebSocket } from '../hooks/useWebSocket';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { confidenceTone, formatConfidence } from '../utils/telemetry';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { getRiskTone, getStatusTone } from '../utils/presentation';
import { getApplicationVisual } from '../utils/apps';

const UNKNOWN_NAMES = new Set(['Unknown', 'Unknown-Device', 'Unnamed Device', '', null, undefined]);

const isNamedDevice = (device) => Boolean(device?.hostname) && !UNKNOWN_NAMES.has(device.hostname);

const deviceDisplayName = (device) => (isNamedDevice(device) ? device.hostname : 'Unnamed Device');

const cleanPart = (part) => {
  const value = String(part || '').trim();
  return value && !['Unknown', 'Unknown Type', '-'].includes(value) ? value : null;
};

const deviceTypeLabel = (device) => {
  if (!device) return 'Identity still being learned';
  const parts = [device.vendor, device.device_type, device.os_family].map(cleanPart).filter(Boolean);
  return parts.length ? parts.join(' · ') : 'Identity still being learned';
};

const normalizeConfidenceScore = (device) => {
  if (!device) return 0.5;
  const explicit = Number(device.identity_confidence);
  if (Number.isFinite(explicit)) return Math.max(0, Math.min(explicit, 1));
  const label = String(device.confidence || '').toLowerCase();
  if (label === 'high') return 0.9;
  if (label === 'medium') return 0.65;
  if (label === 'low') return 0.35;
  return device.mac || isNamedDevice(device) ? 0.65 : 0.5;
};

const confidenceLabel = (device) => {
  const score = normalizeConfidenceScore(device);
  if (score >= 0.85) return 'Strong identity';
  if (score >= 0.55) return 'Usable identity';
  return 'Needs confirmation';
};

const identityExplanation = (device) => {
  if (!device) return 'Gateway can see this IP, but needs more traffic to improve identity.';
  const sources = Array.isArray(device.evidence_sources) ? device.evidence_sources : [];
  if (device.management_mode === 'managed') {
    return 'Installed agent confirms this endpoint and keeps identity stable.';
  }
  if (sources.includes('hostname') && sources.includes('oui')) {
    return 'Gateway matched ARP, hostname, and MAC vendor hints.';
  }
  if (device.mac || device.mac_address) {
    return 'Gateway matched this BYOD asset through ARP and MAC evidence.';
  }
  return 'Gateway can see this IP, but needs more traffic to improve identity.';
};

const activitySummary = (device) => {
  if (!device) return 'No recent activity';
  if (device.top_application) {
    return `${device.top_application}${device.top_domain ? ` via ${device.top_domain}` : ''}`;
  }
  const status = String(device.status || '').toLowerCase();
  if (status === 'online') return 'Online, no current application signal';
  if (status === 'idle') return 'Recently seen, currently quiet';
  return 'No recent activity';
};

const riskExplanation = (device) => {
  if (!device) return '0% risk. No urgent action from current evidence.';
  const level = String(device.risk_level || 'LOW').toUpperCase();
  const score = Math.round(Number(device.risk_score) || 0);
  if (level === 'CRITICAL' || level === 'HIGH') {
    return `${score}% risk. Review this device before trusting activity.`;
  }
  if (level === 'MEDIUM') {
    return `${score}% risk. Watch for repeated or unusual activity.`;
  }
  return `${score}% risk. No urgent action from current evidence.`;
};

const deviceIcon = (device) => {
  if (!device) return 'ri-radar-line';
  const text = `${device.device_type || ''} ${device.vendor || ''} ${device.hostname || ''}`.toLowerCase();
  if (text.includes('phone') || text.includes('android') || text.includes('oppo') || text.includes('iphone')) return 'ri-smartphone-line';
  if (text.includes('printer')) return 'ri-printer-line';
  if (text.includes('tv') || text.includes('chromecast') || text.includes('roku')) return 'ri-tv-line';
  if (text.includes('virtual')) return 'ri-server-line';
  if (text.includes('laptop')) return 'ri-macbook-line';
  return device.management_mode === 'managed' ? 'ri-computer-line' : 'ri-radar-line';
};

const DevicesPage = () => {
  const navigate = useNavigate();
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchValue, setSearchValue] = useState('');
  const [modeFilter, setModeFilter] = useState('all');

  const fetchDevices = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const res = await systemService.getDevices();
      setDevices(res.data || []);
    } catch (err) {
      console.error('Failed to fetch devices', err);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  useVisibilityPolling(() => fetchDevices({ background: true }), 5000);

  const handleDeviceEvent = useCallback((eventData) => {
    const update = eventData?.data;
    if (!update || !update.ip) return;
    setDevices((prev) => {
      const idx = prev.findIndex((device) => device.ip === update.ip);
      if (idx >= 0) {
        const next = [...prev];
        next[idx] = { ...next[idx], ...update };
        return next;
      }
      return [update, ...prev];
    });
  }, []);

  useWebSocket('device_event', handleDeviceEvent);

  const stats = useMemo(() => {
    const named = devices.filter((device) => isNamedDevice(device)).length;
    const managed = devices.filter((device) => device.management_mode === 'managed').length;
    const highRisk = devices.filter((device) => ['HIGH', 'CRITICAL'].includes(device.risk_level)).length;
    const identityResolved = devices.filter((device) => device.identity_key || device.mac || device.ip).length;
    const online = devices.filter((device) => String(device.status || '').toLowerCase() === 'online' || device.is_online).length;
    const activeApps = new Set(devices.map((device) => device.top_application).filter(Boolean));
    const needsIdentity = devices.filter((device) => normalizeConfidenceScore(device) < 0.55).length;
    return { named, managed, highRisk, identityResolved, online, activeApps: activeApps.size, needsIdentity };
  }, [devices]);

  const visibleDevices = useMemo(() => {
    return devices.filter((device) => {
      const matchesMode = modeFilter === 'all' || device.management_mode === modeFilter;
      const haystack = [
        device.hostname,
        device.ip,
        device.mac,
        device.mac_address,
        device.vendor,
        device.device_type,
        device.top_application,
        device.top_domain,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      const matchesSearch = haystack.includes(searchValue.trim().toLowerCase());
      return matchesMode && matchesSearch;
    });
  }, [devices, modeFilter, searchValue]);

  const pageInsights = useMemo(() => {
    const byodCount = devices.length - stats.managed;
    const activeDevice = devices.find((device) => device.top_application) || devices.find((device) => device.is_online);
    const riskCopy = stats.highRisk > 0
      ? `${stats.highRisk} high-risk device${stats.highRisk === 1 ? '' : 's'} need review.`
      : 'No high-risk devices in the current inventory.';
    const identityCopy = stats.needsIdentity > 0
      ? `${stats.needsIdentity} device${stats.needsIdentity === 1 ? '' : 's'} need more identity evidence.`
      : 'Device identity is usable across the visible inventory.';
    const activityCopy = activeDevice
      ? `${deviceDisplayName(activeDevice)} is ${activitySummary(activeDevice).toLowerCase()}.`
      : 'No active device activity is visible yet.';
    return { byodCount, riskCopy, identityCopy, activityCopy };
  }, [devices, stats]);

  const columns = [
    {
      key: 'device',
      label: 'Device',
      render: (row) => (
        <div className="nv-device-cell">
          <span className="nv-device-cell__avatar">
            <i className={deviceIcon(row)}></i>
          </span>
          <div className="nv-device-cell__copy">
            <div className="nv-table__primary">{deviceDisplayName(row)}</div>
            <div className="nv-table__meta">{deviceTypeLabel(row)}</div>
            <div className="nv-device-cell__hint">{identityExplanation(row)}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'understanding',
      label: 'Understanding',
      render: (row) => (
        <div className="nv-explain-stack">
          <div className="nv-chipline">
            <StatusBadge tone={row.management_mode === 'managed' ? 'success' : 'neutral'} icon={row.management_mode === 'managed' ? 'ri-shield-check-line' : 'ri-wifi-line'}>
              {row.management_mode === 'managed' ? 'Managed' : 'BYOD'}
            </StatusBadge>
            <StatusBadge tone={confidenceTone(normalizeConfidenceScore(row))} icon="ri-fingerprint-line">
              {confidenceLabel(row)}
            </StatusBadge>
          </div>
          <div className="nv-table__meta">{formatConfidence(normalizeConfidenceScore(row))} identity confidence</div>
        </div>
      ),
    },
    {
      key: 'activity',
      label: 'What It Is Doing',
      render: (row) => {
        const visual = getApplicationVisual(row.top_application);
        return (
          <div className="nv-activity-cell">
            {row.top_application ? (
              <span className="nv-activity-cell__icon" style={{ '--nv-app-accent': visual.accent }}>
                <i className={visual.icon}></i>
              </span>
            ) : (
              <span className="nv-activity-cell__icon nv-activity-cell__icon--muted">
                <i className="ri-pause-circle-line"></i>
              </span>
            )}
            <div>
              <div className="nv-table__primary">{row.top_application || 'Idle'}</div>
              <div className="nv-table__meta">{activitySummary(row)}</div>
            </div>
          </div>
        );
      },
    },
    {
      key: 'risk',
      label: 'Risk',
      render: (row) => (
        <div className="nv-explain-stack">
          <StatusBadge tone={getRiskTone(row.risk_level)}>{Math.round(row.risk_score || 0)}% {row.risk_level || 'LOW'}</StatusBadge>
          <div className="nv-table__meta">{riskExplanation(row)}</div>
        </div>
      ),
    },
    {
      key: 'network',
      label: 'Network',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.ip}</div>
          <div className="nv-table__meta mono">{row.mac || row.mac_address || '-'}</div>
        </>
      ),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => {
        const status = row.status || (row.is_online ? 'Online' : 'Offline');
        return <StatusBadge tone={getStatusTone(status)}>{status}</StatusBadge>;
      },
    },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Inventory"
        title="Device Inventory"
        description="Understand who is on the network, how NetVisor identified each device, what it is doing now, and whether it needs attention."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchDevices()}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard icon="ri-radar-line" label="Visible Devices" value={devices.length} meta={`${stats.managed} managed / ${pageInsights.byodCount} BYOD`} accent="#54c8e8" />
          <MetricCard icon="ri-pulse-line" label="Online Now" value={stats.online} meta={`${stats.activeApps} active app signal${stats.activeApps === 1 ? '' : 's'}`} accent="#2dd4bf" />
          <MetricCard icon="ri-fingerprint-line" label="Named Devices" value={stats.named} meta={`${stats.needsIdentity} need better identity evidence`} accent="#60a5fa" />
          <MetricCard icon="ri-shield-flash-line" label="Needs Action" value={stats.highRisk} meta="High or critical risk devices" accent="#fb7185" />
        </div>
      )}

      {!loading ? (
        <SectionCard title="Network Understanding" caption="Plain-language Readout" className="nv-section--clarity">
          <div className="nv-device-brief">
            <div className="nv-device-brief__lead">
              <span className="nv-device-brief__icon">
                <i className="ri-sparkling-2-line"></i>
              </span>
              <div>
                <h2>{pageInsights.activityCopy}</h2>
                <p>Use this page as the device map: identity, activity, and risk are separated so you can trust what each signal means.</p>
              </div>
            </div>
            <div className="nv-device-brief__cards">
              <div className="nv-mini-explainer">
                <span>Identity</span>
                <strong>{pageInsights.identityCopy}</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Risk</span>
                <strong>{pageInsights.riskCopy}</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Next step</span>
                <strong>Click any row to inspect applications, traffic, and evidence for that device.</strong>
              </div>
            </div>
          </div>
        </SectionCard>
      ) : null}

      <SectionCard title="Assets" caption="Explainable Inventory">
        <div className="nv-filterbar">
          <div className="nv-filterbar__group">
            <label className="nv-field nv-field--grow">
              <i className="ri-search-line"></i>
              <input
                type="search"
                value={searchValue}
                onChange={(event) => setSearchValue(event.target.value)}
                placeholder="Search hostname, IP, MAC, vendor, app..."
              />
            </label>
            <label className="nv-field">
              <select value={modeFilter} onChange={(event) => setModeFilter(event.target.value)}>
                <option value="all">All Modes</option>
                <option value="managed">Managed</option>
                <option value="byod">BYOD</option>
              </select>
            </label>
          </div>
          <div className="nv-filterbar__hint">
            Showing {visibleDevices.length} of {devices.length} devices. Rows are clickable.
          </div>
        </div>

        {loading ? (
          <TableSkeleton rows={6} />
        ) : (
          <DataTable
            columns={columns}
            rows={visibleDevices}
            rowKey={(row, index) => row.id || row.ip || index}
            onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.ip)}`)}
            emptyTitle="No devices found"
            emptyDescription="Adjust the filters or wait for the latest discovery and traffic feeds to refresh."
          />
        )}
      </SectionCard>
    </div>
  );
};

export default DevicesPage;

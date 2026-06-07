import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { systemService } from '../services/api';
import { formatRuntime, getApplicationVisual, isNetworkServiceApplication } from '../utils/apps';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatByteCount, getStatusTone } from '../utils/presentation';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import Tabs from '../components/V2/Tabs';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';
import { beautifyDpiUrl } from '../utils/webNoise';
import { getWebEvidencePrimaryLabel, getWebEvidenceScopeLabel, normalizeWebRiskLevel } from '../utils/webEvidence';

const parseTimestampValue = (value) => {
  if (!value) {
    return 0;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

const formatRelativeTime = (value) => {
  const parsed = parseTimestampValue(value);
  if (!parsed) {
    return 'N/A';
  }

  const delta = Math.max(Date.now() - parsed, 0);
  const seconds = Math.round(delta / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
};

const aggregateDeviceRows = (rows) => {
  const grouped = new Map();

  rows.forEach((row) => {
    const deviceIp = row.device_ip;
    if (!deviceIp) {
      return;
    }

    const current = grouped.get(deviceIp) || {
      ...row,
      bandwidth_bytes: 0,
      runtime_seconds: 0,
      session_count: 0,
      active_session_count: 0,
      last_seen_value: 0,
    };

    current.bandwidth_bytes += Number(row.bandwidth_bytes) || 0;
    current.runtime_seconds = Math.max(current.runtime_seconds || 0, Number(row.runtime_seconds) || 0);
    current.session_count += Number(row.session_count) || 1;
    current.active_session_count += Number(row.active_session_count) || (row.status === 'Active' ? 1 : 0);

    const lastSeenValue = parseTimestampValue(row.last_seen);
    if (lastSeenValue >= (current.last_seen_value || 0)) {
      current.last_seen_value = lastSeenValue;
      current.last_seen = row.last_seen;
    }

    current.status = current.active_session_count > 0 ? 'Active' : 'Idle';
    current.hostname = current.hostname || row.hostname;
    current.management_mode = current.management_mode || row.management_mode;

    grouped.set(deviceIp, current);
  });

  return Array.from(grouped.values()).sort((left, right) => (
    (right.active_session_count || 0) - (left.active_session_count || 0)
    || (right.bandwidth_bytes || 0) - (left.bandwidth_bytes || 0)
    || (right.last_seen_value || 0) - (left.last_seen_value || 0)
    || String(left.device_ip).localeCompare(String(right.device_ip))
  ));
};

const deviceDisplayName = (row) => {
  const hostname = String(row.hostname || '').trim();
  if (hostname && !['Unknown', 'Unknown-Device', 'Unnamed Device'].includes(hostname)) {
    return hostname;
  }
  return row.device_ip || 'Unknown device';
};

const deviceIdentityHint = (row) => {
  if (row.management_mode === 'managed') {
    return 'Managed endpoint. Agent identity is available.';
  }
  if (row.hostname) {
    return 'Gateway observed hostname and network activity.';
  }
  return 'Gateway observed this device by IP traffic.';
};

const deviceUsageSummary = (row, appName) => {
  const sessions = Number(row.session_count) || 0;
  const active = Number(row.active_session_count) || 0;
  if (active > 0) {
    return `${active} live ${appName} signal${active === 1 ? '' : 's'} now`;
  }
  if (sessions > 1) {
    return `${sessions} sessions folded into this row`;
  }
  return 'Historical usage in the 24-hour window';
};

const ApplicationDevicesPage = () => {
  const navigate = useNavigate();
  const { appName } = useParams();
  const decodedAppName = decodeURIComponent(appName || 'Other');
  const isNetworkService = isNetworkServiceApplication(decodedAppName);
  const [loading, setLoading] = useState(true);
  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const [workspaceGroups, setWorkspaceGroups] = useState([]);
  const [workspaceSummary, setWorkspaceSummary] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const deviceRows = useMemo(() => aggregateDeviceRows(devices), [devices]);
  const evidenceRows = useMemo(() => {
    return [...events]
      .map((row) => ({
        ...row,
        last_seen_value: parseTimestampValue(row.last_seen || row.timestamp || row.created_at),
      }))
      .sort((left, right) => (right.last_seen_value || 0) - (left.last_seen_value || 0));
  }, [events]);

  const groupedEvidenceRows = useMemo(() => {
    if (workspaceGroups.length > 0) {
      return workspaceGroups.map((row) => ({
        ...row,
        page_urls: Array.isArray(row.page_urls) ? row.page_urls : [],
        page_titles: Array.isArray(row.page_titles) ? row.page_titles : [],
        content_ids: Array.isArray(row.content_ids) ? row.content_ids : [],
        search_queries: Array.isArray(row.search_queries) ? row.search_queries : [],
      }));
    }

    const groups = new Map();

    evidenceRows.forEach((row) => {
      const browser = String(row.browser_name || row.process_name || 'Unknown').trim().toLowerCase();
      const domain = String(row.base_domain || row.domain || 'unknown').trim().toLowerCase();
      const title = String(row.page_title || '').trim().toLowerCase();
      const query = String(row.search_query || '').trim().toLowerCase();
      const contentId = String(row.content_id || '').trim().toLowerCase();
      const pageUrl = String(row.page_url || '').trim().toLowerCase();
      const groupKey = `${browser}|${domain}|${contentId || query || title || pageUrl || 'session'}`;

      const current = groups.get(groupKey) || {
        group_key: groupKey,
        browser_name: row.browser_name || row.process_name || 'Unknown',
        process_name: row.process_name || 'unknown',
        page_title: row.page_title || row.title || 'Untitled page',
        page_url: row.page_url || row.base_domain || row.domain || '',
        base_domain: row.base_domain || row.domain || 'Unknown',
        content_category: row.content_category || 'web',
        content_id: row.content_id || null,
        search_query: row.search_query || null,
        risk_level: row.risk_level || 'safe',
        confidence_score: Number(row.confidence_score) || 0,
        event_count: 0,
        last_seen_value: 0,
        last_seen: row.last_seen || row.timestamp || row.created_at || '',
        page_titles: new Set(),
        search_queries: new Set(),
        content_ids: new Set(),
        page_urls: new Set(),
        sources: new Set(),
      };

      current.event_count += 1;
      current.confidence_score = Math.max(current.confidence_score, Number(row.confidence_score) || 0);
      current.risk_level = normalizeWebRiskLevel(row.risk_level || current.risk_level);
      current.sources.add(row.device_ip || 'unknown');
      if (row.page_title) current.page_titles.add(row.page_title);
      if (row.search_query) current.search_queries.add(row.search_query);
      if (row.content_id) current.content_ids.add(row.content_id);
      if (row.page_url) current.page_urls.add(row.page_url);
      if (row.page_title && !row.page_url) current.page_urls.add(row.page_title);

      if ((row.last_seen_value || 0) >= (current.last_seen_value || 0)) {
        current.last_seen_value = row.last_seen_value || 0;
        current.last_seen = row.last_seen || row.timestamp || row.created_at || current.last_seen;
        current.page_title = row.page_title || row.title || current.page_title;
        current.page_url = row.page_url || row.base_domain || row.domain || current.page_url;
        current.base_domain = row.base_domain || row.domain || current.base_domain;
      }

      groups.set(groupKey, current);
    });

    return Array.from(groups.values())
      .map((row) => ({
        ...row,
        page_titles: Array.from(row.page_titles),
        search_queries: Array.from(row.search_queries),
        content_ids: Array.from(row.content_ids),
        page_urls: Array.from(row.page_urls),
        sources: Array.from(row.sources),
      }))
      .sort((left, right) => (right.last_seen_value || 0) - (left.last_seen_value || 0));
  }, [evidenceRows, workspaceGroups]);

  const fetchDevices = useCallback(async () => {
    try {
      const res = await systemService.getAppWorkspace(decodedAppName);
      setDevices(res.data?.devices || []);
      setEvents(res.data?.web_activity || []);
      setWorkspaceGroups(res.data?.web_evidence_groups || []);
      setWorkspaceSummary(res.data?.summary || null);
    } catch (err) {
      console.error('Failed to fetch application devices or events', err);
    } finally {
      setLoading(false);
    }
  }, [decodedAppName]);

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 5000);
    return () => clearInterval(interval);
  }, [fetchDevices]);

  const stats = useMemo(() => {
    return deviceRows.reduce(
      (acc, device) => {
        acc.total += 1;
        acc.active += device.status === 'Active' ? 1 : 0;
        acc.bandwidthBytes += device.bandwidth_bytes || 0;
        acc.runtimeSeconds += device.runtime_seconds || 0;
        return acc;
      },
      { total: 0, active: 0, bandwidthBytes: 0, runtimeSeconds: 0 },
    );
  }, [deviceRows]);

  const workspaceStats = useMemo(() => ({
    deviceCount: workspaceSummary?.device_count ?? stats.total,
    activeDeviceCount: workspaceSummary?.active_device_count ?? stats.active,
    bandwidthBytes: workspaceSummary?.bandwidth_bytes ?? stats.bandwidthBytes,
    eventCount: workspaceSummary?.event_count ?? evidenceRows.length,
    groupCount: workspaceSummary?.group_count ?? groupedEvidenceRows.length,
    lastSeen: workspaceSummary?.last_seen ?? (groupedEvidenceRows[0]?.last_seen || ''),
  }), [groupedEvidenceRows, stats.active, stats.bandwidthBytes, stats.total, evidenceRows.length, workspaceSummary]);

  const evidenceStats = useMemo(() => {
    const domainCounts = new Map();
    const browserCounts = new Map();
    const queryCounts = new Map();

    evidenceRows.forEach((row) => {
      const domain = String(row.base_domain || row.domain || '').trim() || 'Unknown';
      const browser = String(row.browser_name || row.process_name || 'Unknown').trim() || 'Unknown';
      const query = String(row.search_query || row.page_title || row.content_id || '').trim();

      domainCounts.set(domain, (domainCounts.get(domain) || 0) + 1);
      browserCounts.set(browser, (browserCounts.get(browser) || 0) + 1);
      if (query) {
        queryCounts.set(query, (queryCounts.get(query) || 0) + 1);
      }
    });

    return {
      topDomain: Array.from(domainCounts.entries()).sort((a, b) => b[1] - a[1])[0] || ['-', 0],
      topBrowser: Array.from(browserCounts.entries()).sort((a, b) => b[1] - a[1])[0] || ['-', 0],
      topQuery: Array.from(queryCounts.entries()).sort((a, b) => b[1] - a[1])[0] || ['-', 0],
    };
  }, [evidenceRows]);

  const groupedEvidenceStats = useMemo(() => {
    const browsers = new Map();
    const domains = new Map();
    groupedEvidenceRows.forEach((row) => {
      const browser = row.browser_name || 'Unknown';
      const domain = row.base_domain || 'Unknown';
      browsers.set(browser, (browsers.get(browser) || 0) + 1);
      domains.set(domain, (domains.get(domain) || 0) + 1);
    });
    return {
      browserCount: browsers.size,
      domainCount: domains.size,
      topBrowser: Array.from(browsers.entries()).sort((a, b) => b[1] - a[1])[0] || ['-', 0],
      topDomain: Array.from(domains.entries()).sort((a, b) => b[1] - a[1])[0] || ['-', 0],
    };
  }, [groupedEvidenceRows]);

  const appNarrative = useMemo(() => {
    const name = decodedAppName.toLowerCase();
    if (name.includes('google')) {
      return {
        title: 'Search and service activity',
        description: 'Shows searches, result-page visits, and Google service calls grouped into analyst-friendly evidence blocks.',
      };
    }
    if (name.includes('chatgpt')) {
      return {
        title: 'Conversation and AI activity',
        description: 'Shows ChatGPT sessions, page transitions, and AI-related browser evidence grouped by browser and content.',
      };
    }
    if (name.includes('youtube')) {
      return {
        title: 'Streaming and media activity',
        description: 'Shows video sessions, watch pages, and media requests grouped into a single browsing story.',
      };
    }
    return {
      title: 'Application activity',
      description: 'Shows browser evidence grouped by domain, query, and session context for this application.',
    };
  }, [decodedAppName]);

  const pageReadout = useMemo(() => {
    const topDevice = deviceRows[0];
    const topDeviceName = topDevice ? deviceDisplayName(topDevice) : 'No device';
    const browserEvidenceCopy = workspaceStats.groupCount > 0
      ? `${workspaceStats.groupCount} evidence group${workspaceStats.groupCount === 1 ? '' : 's'} available.`
      : 'No browser evidence mapped yet.';
    const usageCopy = topDevice
      ? `${decodedAppName} is most visible on ${topDeviceName}.`
      : `${decodedAppName} has no device usage in this window.`;
    const trafficCopy = stats.active > 0
      ? `${stats.active} active device${stats.active === 1 ? '' : 's'} using it now.`
      : 'No active device is using it right now.';
    const nextStepCopy = workspaceStats.groupCount > 0
      ? 'Open evidence to review page, domain, and browser context.'
      : 'Wait for inspected browser activity or check device traffic.';
    return { browserEvidenceCopy, nextStepCopy, trafficCopy, usageCopy };
  }, [decodedAppName, deviceRows, stats.active, workspaceStats.groupCount]);

  const detailTabs = useMemo(() => ([
    { value: 'overview', label: 'Overview', icon: 'ri-dashboard-line' },
    { value: 'evidence', label: 'Evidence', icon: 'ri-file-list-line' },
    { value: 'raw', label: 'Raw', icon: 'ri-code-line' },
  ]), []);

  const visual = getApplicationVisual(decodedAppName);
  const applicationKindLabel = isNetworkService ? 'Network service' : 'Product app';

  const deviceColumns = [
    {
      key: 'device_ip',
      label: 'Device',
      render: (row) => (
        <div className="nv-device-cell">
          <span className="nv-device-cell__avatar">
            <i className={row.management_mode === 'managed' ? 'ri-computer-line' : 'ri-radar-line'}></i>
          </span>
          <div className="nv-device-cell__copy">
            <div className="nv-table__primary">{deviceDisplayName(row)}</div>
            <div className="nv-table__meta mono">{row.device_ip}</div>
            <div className="nv-device-cell__hint">{deviceIdentityHint(row)}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'usage',
      label: 'Usage Meaning',
      render: (row) => (
        <div className="nv-explain-stack">
          <div className="nv-chipline">
            <StatusBadge tone={row.management_mode === 'managed' ? 'success' : 'neutral'}>{row.management_mode === 'managed' ? 'Managed' : 'BYOD'}</StatusBadge>
            <StatusBadge tone={getStatusTone(row.status)}>{row.status}</StatusBadge>
          </div>
          <div className="nv-table__meta">{deviceUsageSummary(row, decodedAppName)}</div>
        </div>
      ),
    },
    {
      key: 'traffic',
      label: 'Traffic',
      render: (row) => (
        <div className="nv-explain-stack">
          <div className="nv-table__primary mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes)}</div>
          <div className="nv-table__meta">{row.runtime || formatRuntime(row.runtime_seconds)} observed runtime</div>
        </div>
      ),
    },
    {
      key: 'freshness',
      label: 'Freshness',
      render: (row) => (
        <div className="nv-explain-stack">
          <div className="nv-table__primary mono">{formatRelativeTime(row.last_seen)}</div>
          <div className="nv-table__meta">{row.last_seen ? formatUtcTimestampToLocal(row.last_seen) : 'N/A'}</div>
        </div>
      ),
    },
  ];

  const webColumns = [
    {
      key: 'event',
      label: 'Browser Evidence',
      render: (row) => (
        <>
          <div className="nv-table__primary">{getWebEvidencePrimaryLabel(row)}</div>
          <div className="nv-table__meta" title={row.page_url || row.base_domain || row.domain}>
            {beautifyDpiUrl(row.page_url || row.base_domain || row.domain || row.page_urls?.[0])}
          </div>
          <div className="nv-table__meta">{getWebEvidenceScopeLabel(row).text}</div>
        </>
      ),
    },
    {
      key: 'browser',
      label: 'Browser',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.browser_name || 'Unknown'}</div>
          <div className="nv-table__meta">{row.process_name || '-'}</div>
        </>
      ),
    },
    {
      key: 'context',
      label: 'Session Context',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.content_category || 'web'}</div>
          <div className="nv-table__meta">
            {row.search_queries?.[0]
              || row.content_ids?.[0]
              || row.page_titles?.[0]
              || row.page_urls?.[0]
              || row.search_query
              || row.content_id
              || row.page_title
              || '-'}
          </div>
        </>
      ),
    },
    {
      key: 'risk',
      label: 'Risk',
      render: (row) => <StatusBadge tone={getStatusTone(normalizeWebRiskLevel(row.risk_level))}>{normalizeWebRiskLevel(row.risk_level)}</StatusBadge>,
    },
    { key: 'time', label: 'Time', render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.timestamp)}</span> },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Inventory"
        title={decodedAppName}
        description={isNetworkService
          ? 'Inspect which devices are producing this service bucket, how active they are, and whether any associated browser inspection activity is already visible.'
          : 'Inspect which devices are using this application, how active they are, and whether any associated browser inspection activity is already visible.'}
        actions={(
          <>
            <Link className="nv-button nv-button--secondary" to="/apps">
              <i className="ri-arrow-left-line"></i>
              Back
            </Link>
            <button type="button" className="nv-button nv-button--secondary" onClick={fetchDevices}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </>
        )}
      >
        <div className="nv-pill-card" style={{ width: 'fit-content' }}>
          <div className="nv-pill-card__icon" style={{ color: visual.accent, background: visual.background, borderColor: `${visual.accent}33` }}>
            <i className={visual.icon}></i>
          </div>
          <div className="nv-pill-card__content">
            <strong>{decodedAppName}</strong>
            <span>{applicationKindLabel} coverage grouped by device across the last 24 hours</span>
          </div>
        </div>
      </PageHeader>

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard icon="ri-macbook-line" label="Devices" value={stats.total} meta={`${stats.active} active / ${stats.total - stats.active} idle`} accent="#54c8e8" />
          <MetricCard icon="ri-exchange-funds-line" label="Bandwidth" value={formatByteCount(workspaceStats.bandwidthBytes)} meta="24 hour application window" accent="#2dd4bf" />
          <MetricCard icon="ri-time-line" label="Runtime" value={formatRuntime(stats.runtimeSeconds)} meta="Aggregated coverage span across visible devices" accent="#60a5fa" />
          <MetricCard icon="ri-shield-user-line" label="Managed Coverage" value={deviceRows.filter((device) => device.management_mode === 'managed').length} meta="Managed devices using this application" accent="#fbbf24" />
        </div>
      )}

      {!loading ? (
        <SectionCard title="Application Readout" caption="Plain-language investigation summary" className="nv-section--clarity">
          <div className="nv-app-detail-brief">
            <div className="nv-app-detail-brief__lead">
              <span className="nv-app-detail-brief__icon" style={{ '--nv-app-accent': visual.accent }}>
                <i className={visual.icon}></i>
              </span>
              <div>
                <h2>{pageReadout.usageCopy}</h2>
                <p>{appNarrative.description}</p>
              </div>
            </div>
            <div className="nv-app-detail-brief__cards">
              <div className="nv-mini-explainer">
                <span>Devices</span>
                <strong>{pageReadout.trafficCopy}</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Evidence</span>
                <strong>{pageReadout.browserEvidenceCopy}</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Kind</span>
                <strong>{applicationKindLabel}. {isNetworkService ? 'Treat as protocol visibility.' : 'Treat as user-facing app usage.'}</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Next step</span>
                <strong>{pageReadout.nextStepCopy}</strong>
              </div>
            </div>
          </div>
        </SectionCard>
      ) : null}

      <SectionCard title="Device Coverage" caption="One row per device with repeated sessions folded together">
        {loading ? (
          <TableSkeleton rows={5} />
        ) : (
          <DataTable
            columns={deviceColumns}
            rows={deviceRows}
            rowKey={(row) => `${decodedAppName}-${row.device_ip}`}
            onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.device_ip)}`)}
            emptyTitle="No devices are currently using this application"
            emptyDescription="Sessions for this application have not appeared in the current 24-hour window."
          />
        )}
      </SectionCard>

      <SectionCard
        title="Application Browsing Evidence"
        caption={appNarrative.description}
        aside={(
            <div className="nv-inline-actions">
            <StatusBadge tone={(groupedEvidenceRows.length > 0) ? 'success' : 'neutral'}>{workspaceStats.groupCount} groups</StatusBadge>
            <StatusBadge tone="accent">{groupedEvidenceStats.topDomain[0]} x {groupedEvidenceStats.topDomain[1]}</StatusBadge>
          </div>
        )}
      >
        {loading ? (
          <TableSkeleton rows={5} />
        ) : (
          <>
            <Tabs value={activeTab} onChange={setActiveTab} items={detailTabs} />
            <div className="nv-metric-grid" style={{ marginBottom: '1rem' }}>
              <MetricCard icon="ri-search-line" label="Top Query / Page" value={evidenceStats.topQuery[0] || '-'} meta={`${evidenceStats.topQuery[1] || 0} occurrences`} accent={visual.accent} />
              <MetricCard icon="ri-global-line" label="Top Domain" value={groupedEvidenceStats.topDomain[0] || '-'} meta={`${groupedEvidenceStats.domainCount} domains / ${workspaceStats.groupCount} groups`} accent="#54c8e8" />
              <MetricCard icon="ri-window-line" label="Top Browser" value={groupedEvidenceStats.topBrowser[0] || '-'} meta={`${groupedEvidenceStats.browserCount} browsers / ${workspaceStats.groupCount} groups`} accent="#2dd4bf" />
              <MetricCard icon="ri-history-line" label="Latest Activity" value={groupedEvidenceRows[0] ? formatRelativeTime(groupedEvidenceRows[0].last_seen || groupedEvidenceRows[0].timestamp || '') : 'N/A'} meta={groupedEvidenceRows[0]?.page_title || 'No recent browser evidence'} accent="#fbbf24" />
            </div>
            {activeTab === 'overview' ? (
              <div className="nv-stack" style={{ gap: '1rem' }}>
                <div className="nv-stack" style={{ gap: '0.5rem' }}>
                  <div className="nv-section__caption">{appNarrative.title}</div>
                  <h3 className="nv-section__title">{appNarrative.description}</h3>
                </div>
                <div className="nv-metric-grid">
                  <MetricCard icon="ri-computer-line" label="Devices" value={workspaceStats.deviceCount} meta={`${workspaceStats.activeDeviceCount} active in the last 24 hours`} accent={visual.accent} />
                  <MetricCard icon="ri-group-line" label="Evidence Groups" value={workspaceStats.groupCount} meta={`${workspaceStats.eventCount} raw events collapsed into groups`} accent="#54c8e8" />
                  <MetricCard icon="ri-window-line" label="Browsers" value={groupedEvidenceStats.browserCount} meta="Grouped browser/process coverage" accent="#2dd4bf" />
                  <MetricCard icon="ri-shield-check-line" label="Risk Signal" value={groupedEvidenceRows[0] ? normalizeWebRiskLevel(groupedEvidenceRows[0].risk_level) : 'SAFE'} meta="Highest-priority grouped evidence" accent="#fbbf24" />
                </div>
                <DataTable
                  columns={webColumns}
                  rows={groupedEvidenceRows.slice(0, 8)}
                  rowKey={(row, index) => row.group_key || `${row.device_ip || 'device'}-${index}`}
                  onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.device_ip)}/web-activity`)}
                  emptyTitle="No browser evidence for this application yet"
                  emptyDescription="As browsing occurs in this app, it will appear here grouped by domain, query, and browser session."
                />
              </div>
            ) : activeTab === 'evidence' ? (
              <DataTable
                columns={webColumns}
                rows={groupedEvidenceRows}
                rowKey={(row, index) => row.group_key || `${row.device_ip || 'device'}-${index}`}
                onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.device_ip)}/web-activity`)}
                emptyTitle="No browser evidence for this application yet"
                emptyDescription="As browsing occurs in this app, it will appear here grouped by domain, query, and browser session."
              />
            ) : (
              <DataTable
                columns={webColumns}
                rows={events}
                rowKey={(row, index) => row.id || `${row.device_ip || 'device'}-${index}`}
                onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.device_ip)}`)}
                emptyTitle="No recent inspected web activity"
                emptyDescription="Either inspection is disabled for the relevant devices or this application does not currently map to allowlisted inspected traffic."
              />
            )}
          </>
        )}
      </SectionCard>
    </div>
  );
};

export default ApplicationDevicesPage;

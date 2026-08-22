import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';
import { systemService } from '../services/api';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import Tabs from '../components/V2/Tabs';
import WebEvidenceDrawer from '../components/DPI/WebEvidenceDrawer';
import DpiSetupGuide from '../components/DPI/DpiSetupGuide';
import DpiCategoryChart from '../components/DPI/DpiCategoryChart';
import ErrorState from '../components/V2/ErrorState';
import { TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatBrowserLabel, getRiskTone } from '../utils/presentation';
import { getWebEvidencePrimaryLabel, getWebEvidenceScopeLabel, matchesWebEvidenceFilters, normalizeWebRiskLevel } from '../utils/webEvidence';
import { beautifyDpiUrl, isDpiNoise } from '../utils/webNoise';
import { formatRelativeTime } from '../utils/intelTranslator';
import { exportToCsv, exportToJson } from '../utils/exportUtils';

const MAX_EVENTS = 100;

const DpiDashboard = () => {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [evidenceGroups, setEvidenceGroups] = useState([]);
  const [status, setStatus] = useState({ state: 'disabled', proxy: 'stopped', certificate: 'not_installed', lastActivity: null, eps: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({ query: '', domain: '', risk: 'all', category: 'all' });
  const [hideNoise, setHideNoise] = useState(true);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [showGuide, setShowGuide] = useState(false);
  const [activeTab, setActiveTab] = useState('groups');

  const tabItems = [
    { value: 'groups', label: 'Evidence Groups', icon: 'ri-folder-shield-2-line' },
    { value: 'raw', label: 'Raw Activities', icon: 'ri-list-check-2' },
  ];

  const fetchData = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    setError(null);
    try {
      const [statusRes, eventsRes, groupsRes] = await Promise.all([
        systemService.getDpiGlobalStatus(),
        systemService.getGlobalWebActivity(100),
        systemService.getGlobalWebEvidenceGroups(50),
      ]);
      setStatus(statusRes.data || { state: 'disabled', proxy: 'stopped', certificate: 'not_installed', lastActivity: null, eps: 0 });
      const payload = Array.isArray(eventsRes.data) ? eventsRes.data : (eventsRes.data?.activity || []);
      
      setEvents((currentEvents) => {
        const map = new Map();
        payload.forEach((item) => map.set(item.id || `${item.page_url}-${item.timestamp}`, item));
        currentEvents.filter((item) => item.isNew).forEach((item) => {
          const key = item.id || `${item.page_url}-${item.timestamp}`;
          if (!map.has(key)) {
            map.set(key, item);
          }
        });
        return Array.from(map.values()).slice(0, MAX_EVENTS);
      });

      const groupedPayload = Array.isArray(groupsRes.data) ? groupsRes.data : (groupsRes.data?.activity || []);
      setEvidenceGroups(groupedPayload);
    } catch (err) {
      console.error('Failed to load DPI dashboard', err);
      if (!background) {
        setError('Failed to load web inspection telemetry from the NetVisor gateway.');
      }
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleDpiEvent = useCallback((event) => {
    setEvents((prev) => [{ ...event, isNew: true }, ...prev].slice(0, MAX_EVENTS));
    setStatus((current) => ({ ...current, lastActivity: event.timestamp || event.last_seen }));
  }, []);

  const { status: wsStatus } = useWebSocket('dpi_event', handleDpiEvent);

  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      if (hideNoise && isDpiNoise(event)) return false;
      if (!matchesWebEvidenceFilters(event, filters)) return false;
      if (filters.category === 'streaming') {
        const url = String(event.page_url || event.domain || '').toLowerCase();
        return url.includes('youtube') || url.includes('youtu.be') || url.includes('video') || event.content_category === 'streaming';
      }
      if (filters.category === 'search') {
        return Boolean(event.search_query || event.query);
      }
      if (filters.category === 'high_risk') {
        const risk = normalizeWebRiskLevel(event.risk_level);
        return risk === 'high' || risk === 'critical';
      }
      return true;
    });
  }, [events, filters, hideNoise]);

  const filteredGroups = useMemo(() => {
    return evidenceGroups.filter((event) => {
      if (hideNoise && isDpiNoise(event)) return false;
      if (!matchesWebEvidenceFilters(event, filters)) return false;
      if (filters.category === 'streaming') {
        const url = String(event.page_url || event.base_domain || '').toLowerCase();
        return url.includes('youtube') || url.includes('youtu.be') || url.includes('video') || event.content_category === 'streaming';
      }
      if (filters.category === 'search') {
        return Boolean(event.search_query || event.search_queries?.length);
      }
      if (filters.category === 'high_risk') {
        const risk = normalizeWebRiskLevel(event.risk_level);
        return risk === 'high' || risk === 'critical';
      }
      return true;
    });
  }, [evidenceGroups, filters, hideNoise]);

  const handleExportCsv = () => {
    if (activeTab === 'groups') {
      const exportCols = [
        { key: 'group_label', label: 'Activity Group' },
        { key: 'device_ip', label: 'Device IP' },
        { key: 'base_domain', label: 'Domain' },
        { key: 'risk_level', label: 'Risk' },
        { key: 'last_seen', label: 'Timestamp' },
      ];
      exportToCsv('dpi-evidence-groups', exportCols, filteredGroups);
    } else {
      const exportCols = [
        { key: 'page_title', label: 'Page Title' },
        { key: 'page_url', label: 'URL' },
        { key: 'device_ip', label: 'Device IP' },
        { key: 'search_query', label: 'Search Query' },
        { key: 'risk_level', label: 'Risk' },
        { key: 'last_seen', label: 'Timestamp' },
      ];
      exportToCsv('dpi-raw-activity', exportCols, filteredEvents);
    }
  };

  const handleExportJson = () => {
    exportToJson(activeTab === 'groups' ? 'dpi-evidence-groups' : 'dpi-raw-activity', activeTab === 'groups' ? filteredGroups : filteredEvents);
  };

  const groupedColumns = [
    {
      key: 'activity',
      label: 'Inspected Activity',
      render: (row) => (
        <>
          <div className="nv-table__primary">{getWebEvidencePrimaryLabel(row)}</div>
          <div className="nv-table__meta">{row.base_domain || row.page_url || '-'}</div>
          <div className="nv-table__meta">{getWebEvidenceScopeLabel(row).text}</div>
        </>
      ),
    },
    {
      key: 'device',
      label: 'Client Device',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.device_ip || '-'}</div>
          <div className="nv-table__meta">{formatBrowserLabel(row.browser_name, row.process_name)}</div>
        </>
      ),
    },
    {
      key: 'scope',
      label: 'Evidence Scope',
      render: (row) => (
        <>
          <div className="nv-table__primary">{getWebEvidenceScopeLabel(row).eventCount} event{getWebEvidenceScopeLabel(row).eventCount === 1 ? '' : 's'}</div>
          <div className="nv-table__meta">{row.content_id || row.content_category || 'Web Session'}</div>
        </>
      ),
    },
    {
      key: 'risk',
      label: 'Risk Posture',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel.toUpperCase()}</StatusBadge>;
      },
    },
    {
      key: 'last_seen',
      label: 'Observed',
      render: (row) => {
        const ts = row.last_seen || row.timestamp || row.created_at;
        return (
          <span className="mono" title={formatUtcTimestampToLocal(ts)}>
            {formatRelativeTime(ts)}
          </span>
        );
      },
    },
  ];

  const rawColumns = [
    {
      key: 'activity',
      label: 'Web Page & URL',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.page_title || 'Untitled Web Session'}</div>
          <div className="nv-table__meta" title={row.page_url || row.base_domain || row.domain}>
            {beautifyDpiUrl(row.page_url || row.base_domain || row.domain)}
          </div>
        </>
      ),
    },
    {
      key: 'device',
      label: 'Client Device',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.device_ip || '-'}</div>
          <div className="nv-table__meta">{formatBrowserLabel(row.browser_name, row.process_name)}</div>
        </>
      ),
    },
    {
      key: 'category',
      label: 'Decoded Content',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.content_category || 'Web'}</div>
          <div className="nv-table__meta">{row.search_query || row.content_id || '-'}</div>
        </>
      ),
    },
    {
      key: 'risk',
      label: 'Risk Posture',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel.toUpperCase()}</StatusBadge>;
      },
    },
    {
      key: 'last_seen',
      label: 'Observed',
      render: (row) => {
        const ts = row.last_seen || row.timestamp || row.created_at;
        return (
          <span className="mono" title={formatUtcTimestampToLocal(ts)}>
            {formatRelativeTime(ts)}
          </span>
        );
      },
    },
  ];

  if (error && !loading && events.length === 0) {
    return (
      <div className="nv-page nv-page--balanced">
        <ErrorState title="Web Inspection Error" message={error} onRetry={() => fetchData()} />
      </div>
    );
  }

  return (
    <div className="nv-page nv-page--balanced">
      <PageHeader
        eyebrow="Deep Packet Inspection"
        title="Web & Decoded Traffic Inspection"
        description="Inspect decrypted browser telemetry, query intent, decoded streaming sessions, and correlated evidence with instant export options."
        actions={(
          <>
            <StatusBadge tone={wsStatus === 'connected' ? 'success' : 'warning'} icon="ri-broadcast-line">
              {wsStatus === 'connected' ? 'Live Stream' : 'Reconnecting'}
            </StatusBadge>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => setShowGuide((prev) => !prev)}>
              <i className={showGuide ? 'ri-book-open-fill' : 'ri-book-open-line'}></i>
              {showGuide ? 'Hide Setup' : 'Browser Proxy Guide'}
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={handleExportCsv} title="Export current view to CSV">
              <i className="ri-file-download-line"></i>
              Export CSV
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={handleExportJson} title="Export current view to JSON">
              <i className="ri-code-line"></i>
              JSON
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchData()}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => setHideNoise((current) => !current)}>
              <i className={hideNoise ? 'ri-filter-2-line' : 'ri-filter-2-fill'}></i>
              {hideNoise ? 'Noise Filtered' : 'Showing Raw'}
            </button>
          </>
        )}
      />

      {showGuide && (
        <div style={{ marginBottom: '1.5rem' }}>
          <DpiSetupGuide inspectionStatus={status} />
        </div>
      )}

      <div className="nv-metric-grid" style={{ marginBottom: '1.5rem' }}>
        <MetricCard icon="ri-navigation-line" label="Inspection State" value={status.state} meta="Global inspection posture" accent="#54c8e8" />
        <MetricCard icon="ri-route-line" label="Proxy Port" value={status.proxy} meta="Explicit agent-side proxy" accent="#60a5fa" />
        <MetricCard icon="ri-award-line" label="Root Certificate" value={status.certificate} meta="CA trust chain" accent="#2dd4bf" />
        <MetricCard icon="ri-flashlight-line" label="Events / Sec" value={(Number(status.eps) || 0).toFixed(1)} meta={status.lastActivity ? `Last activity ${formatRelativeTime(status.lastActivity)}` : 'No recent activity'} accent="#fbbf24" />
      </div>

      <div style={{ marginBottom: '1.5rem' }}>
        <SectionCard title="Web Traffic Category Breakdown" caption="Intent & Protocol Classification">
          <DpiCategoryChart events={events} height={160} />
        </SectionCard>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.5rem' }}>
        <Tabs value={activeTab} onChange={setActiveTab} items={tabItems} />

        {/* Quick Filter Pills */}
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          {[
            { id: 'all', label: 'All Feeds' },
            { id: 'streaming', label: 'YouTube / Media' },
            { id: 'search', label: 'Search Queries' },
            { id: 'high_risk', label: 'High/Critical Risk' },
          ].map((pill) => (
            <button
              key={pill.id}
              type="button"
              className={`nv-button nv-button--xs ${filters.category === pill.id ? 'nv-button--primary' : 'nv-button--secondary'}`}
              onClick={() => setFilters((f) => ({ ...f, category: pill.id }))}
            >
              {pill.label}
            </button>
          ))}
        </div>
      </div>

      <div className="nv-filterbar" style={{ marginBottom: '1.5rem' }}>
        <div className="nv-filterbar__group">
          <label className="nv-field nv-field--grow">
            <i className="ri-search-line"></i>
            <input
              type="search"
              placeholder="Search title, URL, browser, search intent..."
              value={filters.query}
              onChange={(event) => setFilters((current) => ({ ...current, query: event.target.value }))}
            />
          </label>
          <label className="nv-field">
            <input
              type="text"
              placeholder="Domain filter..."
              value={filters.domain}
              onChange={(event) => setFilters((current) => ({ ...current, domain: event.target.value }))}
            />
          </label>
          <label className="nv-field">
            <select value={filters.risk} onChange={(event) => setFilters((current) => ({ ...current, risk: event.target.value }))}>
              <option value="all">All Risk Levels</option>
              <option value="safe">Safe Only</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
        </div>
      </div>

      {activeTab === 'groups' ? (
        <SectionCard title="Correlated Evidence Clusters" caption={`Showing ${filteredGroups.length} aggregated session groups`} className="nv-section--balanced">
          <div className="nv-scroll-region nv-scroll-region--xl">
            {loading ? (
              <TableSkeleton rows={6} />
            ) : (
              <DataTable
                columns={groupedColumns}
                rows={filteredGroups}
                rowKey={(row, index) => row.group_key || `${row.page_url || row.base_domain}-${index}`}
                onRowClick={(row) => setSelectedEvidence(row)}
                emptyTitle="No grouped evidence found"
                emptyDescription="Enable inspection on a managed client device or adjust search filters."
              />
            )}
          </div>
        </SectionCard>
      ) : (
        <SectionCard title="Raw Decoded Web Activity" caption={`Showing ${filteredEvents.length} live stream entries`} className="nv-section--balanced">
          <div className="nv-scroll-region nv-scroll-region--xl">
            {loading ? (
              <TableSkeleton rows={6} />
            ) : (
              <DataTable
                columns={rawColumns}
                rows={filteredEvents}
                rowKey={(row, index) => row.id || `${row.page_url || row.base_domain}-${index}`}
                onRowClick={(row) => setSelectedEvidence(row)}
                emptyTitle="No live DPI activity found"
                emptyDescription="Ensure the client browser proxy is active and certificate is installed."
              />
            )}
          </div>
        </SectionCard>
      )}

      <WebEvidenceDrawer
        open={Boolean(selectedEvidence)}
        item={selectedEvidence}
        onClose={() => setSelectedEvidence(null)}
        footer={selectedEvidence ? (
          <div className="nv-inline-actions">
            {selectedEvidence.device_ip ? (
              <>
                <button type="button" className="nv-button nv-button--secondary" onClick={() => navigate(`/user/${encodeURIComponent(selectedEvidence.device_ip)}`)}>
                  Device Profile
                </button>
                <button type="button" className="nv-button nv-button--primary" onClick={() => navigate(`/user/${encodeURIComponent(selectedEvidence.device_ip)}/web-activity`)}>
                  Deep Dive Timeline
                </button>
              </>
            ) : null}
          </div>
        ) : null}
      />
    </div>
  );
};

export default DpiDashboard;

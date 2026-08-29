import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { systemService } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import Tabs from '../components/V2/Tabs';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import WebEvidenceDrawer from '../components/DPI/WebEvidenceDrawer';
import ErrorState from '../components/V2/ErrorState';
import { TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatBrowserLabel, getRiskTone } from '../utils/presentation';
import { normalizeWebRiskLevel } from '../utils/webEvidence';
import { beautifyDpiUrl, isDpiNoise } from '../utils/webNoise';
import { formatRelativeTime } from '../utils/intelTranslator';
import { exportToCsv, exportToJson } from '../utils/exportUtils';

const DpiActivityPage = () => {
  const { deviceIp } = useParams();
  const decodedIp = decodeURIComponent(deviceIp);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deviceInfo, setDeviceInfo] = useState(null);
  const [filter, setFilter] = useState('all');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [hideNoise, setHideNoise] = useState(true);

  const fetchActivity = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    setError(null);
    try {
      const activityRes = await systemService.getDeviceWebActivity(decodedIp);
      setEvents(activityRes.data?.activity || []);

      const devices = await systemService.getDevices();
      const device = (devices.data || []).find((entry) => entry.ip === decodedIp);
      setDeviceInfo(device || null);
    } catch (err) {
      console.error('Failed to fetch activity', err);
      if (!background) {
        setError(`Failed to fetch web activity for device ${decodedIp}.`);
      }
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, [decodedIp]);

  useEffect(() => {
    fetchActivity();
  }, [fetchActivity]);

  const handleDpiEvent = useCallback((event) => {
    if (event.device_ip === decodedIp) {
      setEvents((prev) => [{ ...event, isNew: true }, ...prev].slice(0, 100));
    }
  }, [decodedIp]);

  useWebSocket('dpi_event', handleDpiEvent);

  const filteredEvents = useMemo(() => {
    let result = events;
    if (hideNoise) {
      result = result.filter((entry) => !isDpiNoise(entry));
    }
    if (filter === 'all') return result;
    if (filter === 'threats') {
      return result.filter((entry) => normalizeWebRiskLevel(entry.risk_level) !== 'safe');
    }
    if (filter === 'streaming') {
      return result.filter((entry) => {
        const url = String(entry.page_url || entry.domain || '').toLowerCase();
        return url.includes('youtube') || url.includes('youtu.be') || url.includes('video') || entry.content_category === 'streaming';
      });
    }
    if (filter === 'search') {
      return result.filter((entry) => Boolean(entry.search_query || entry.query));
    }
    return result.filter((entry) => entry.content_category === filter);
  }, [events, filter, hideNoise]);

  const stats = useMemo(() => {
    const total = events.length;
    const threats = events.filter((entry) => normalizeWebRiskLevel(entry.risk_level) !== 'safe').length;
    const streaming = events.filter((entry) => {
      const url = String(entry.page_url || entry.domain || '').toLowerCase();
      return url.includes('youtube') || url.includes('video') || entry.content_category === 'streaming';
    }).length;
    return { total, threats, streaming };
  }, [events]);

  const handleExportCsv = () => {
    const exportCols = [
      { key: 'page_title', label: 'Activity' },
      { key: 'page_url', label: 'URL' },
      { key: 'content_category', label: 'Category' },
      { key: 'risk_level', label: 'Security' },
      { key: 'last_seen', label: 'Timestamp' },
    ];
    exportToCsv(`device-${decodedIp}-dpi`, exportCols, filteredEvents);
  };

  const handleExportJson = () => {
    exportToJson(`device-${decodedIp}-dpi`, filteredEvents);
  };

  const rawColumns = [
    {
      key: 'activity',
      label: 'Page & Intent',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.page_title || 'Untitled Session'}</div>
          <div className="nv-table__meta" title={row.page_url}>{beautifyDpiUrl(row.page_url || row.base_domain)}</div>
        </>
      ),
    },
    {
      key: 'domain',
      label: 'Domain / Host',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.base_domain || row.domain || '-'}</div>
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
      key: 'time',
      label: 'Observed',
      render: (row) => {
        const ts = row.last_seen || row.timestamp;
        return (
          <span className="mono" title={formatUtcTimestampToLocal(ts)}>
            {formatRelativeTime(ts)}
          </span>
        );
      },
    },
    {
      key: 'risk',
      label: 'Security Posture',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel.toUpperCase()}</StatusBadge>;
      },
    },
  ];

  const filterTabs = [
    { value: 'all', label: 'All Activities', count: events.length },
    { value: 'streaming', label: 'YouTube & Media', count: stats.streaming },
    { value: 'search', label: 'Search Queries' },
    { value: 'threats', label: 'Security Threats', count: stats.threats },
  ];

  if (error && !loading && events.length === 0) {
    return (
      <div className="nv-page nv-page--balanced">
        <ErrorState title="Device Inspection Error" message={error} onRetry={() => fetchActivity()} />
      </div>
    );
  }

  return (
    <div className="nv-page nv-page--balanced">
      <PageHeader
        eyebrow="Device Deep Dive"
        title={`Browser Inspection - ${deviceInfo?.hostname || decodedIp}`}
        description={`Investigate decrypted sessions, search queries, and streaming activity originating from ${decodedIp}.`}
        actions={(
          <>
            <Link className="nv-button nv-button--secondary" to={`/user/${encodeURIComponent(decodedIp)}`}>
              <i className="ri-arrow-left-line"></i>
              Device Profile
            </Link>
            <button type="button" className="nv-button nv-button--secondary" onClick={handleExportCsv} title="Export device logs to CSV">
              <i className="ri-file-download-line"></i>
              Export CSV
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={handleExportJson} title="Export device logs to JSON">
              <i className="ri-code-line"></i>
              JSON
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchActivity()}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => setHideNoise((c) => !c)}>
              <i className={hideNoise ? 'ri-filter-2-line' : 'ri-filter-2-fill'}></i>
              {hideNoise ? 'Noise Filtered' : 'Showing Raw'}
            </button>
          </>
        )}
      />

      <div className="nv-metric-grid" style={{ marginBottom: '1.5rem' }}>
        <MetricCard icon="ri-radar-line" label="Inspected Sessions" value={stats.total} meta="Captured from active browser tabs" accent="#54c8e8" />
        <MetricCard icon="ri-youtube-line" label="Media & Streaming" value={stats.streaming} meta="Video playback & audio feeds" accent="#ef4444" />
        <MetricCard icon="ri-shield-flash-line" label="Security Incidents" value={stats.threats} meta="Flagged non-safe URLs" accent="#fb7185" />
        <MetricCard icon="ri-macbook-line" label="Client Host" value={deviceInfo?.hostname || 'Unknown'} meta={`IP: ${decodedIp}`} accent="#2dd4bf" />
      </div>

      <div style={{ marginBottom: '1.5rem' }}>
        <Tabs value={filter} onChange={setFilter} items={filterTabs} />
      </div>

      <SectionCard title="Inspected Session Timeline" caption={`Showing ${filteredEvents.length} records`} className="nv-section--balanced">
        <div className="nv-scroll-region nv-scroll-region--xl">
          {loading ? (
            <TableSkeleton rows={6} />
          ) : (
            <DataTable
              columns={rawColumns}
              rows={filteredEvents}
              rowKey={(row, index) => row.id || `${row.page_url || row.base_domain}-${index}`}
              onRowClick={(row) => setSelectedEvent(row)}
              emptyTitle="No inspected web activity for this filter"
              emptyDescription="Change the filter category or browse through the client proxy launcher."
            />
          )}
        </div>
      </SectionCard>

      <WebEvidenceDrawer
        open={Boolean(selectedEvent)}
        item={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
};

export default DpiActivityPage;

import { useCallback, useEffect, useMemo, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import ThreatDrawer from '../components/V2/ThreatDrawer';
import ErrorState from '../components/V2/ErrorState';
import { TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { getRiskTone } from '../utils/presentation';

const ThreatsPage = () => {
  const [threats, setThreats] = useState([]);
  const [threatCount, setThreatCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);

  const fetchThreats = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    setError(null);
    try {
      const [res, statsRes] = await Promise.all([
        systemService.getAlerts({
          severity: 'HIGH,CRITICAL',
          resolved: false,
          hours: 24,
          limit: 100,
        }),
        systemService.getStats(),
      ]);
      setThreats(res.data || []);
      setThreatCount(statsRes.data?.high_risk || 0);
    } catch (err) {
      console.error('Failed to fetch threats', err);
      if (!background) {
        setError('Failed to fetch high-risk security alerts from the gateway.');
      }
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  useVisibilityPolling(() => fetchThreats({ background: true }), 15000);

  const criticalCount = useMemo(
    () => threats.filter((entry) => entry.severity === 'CRITICAL').length,
    [threats],
  );

  const topReason = useMemo(() => {
    const counts = new Map();
    threats.forEach((entry) => {
      const reason = entry.breakdown?.primary_detection || entry.message || 'Unspecified';
      counts.set(reason, (counts.get(reason) || 0) + 1);
    });
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0] || ['-', 0];
  }, [threats]);

  const threatColumns = [
    {
      key: 'time',
      label: 'Time',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.timestamp)}</span>,
    },
    {
      key: 'target',
      label: 'Target',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.device_ip || row.src_ip || '-'}</div>
          <div className="nv-table__meta">{row.application || row.domain || 'Network activity'}</div>
        </>
      ),
    },
    {
      key: 'identity',
      label: 'Identity',
      render: (row) => <span className="mono">{row.flow_id ? `Flow ${String(row.flow_id).slice(0, 8)}` : '-'}</span>,
    },
    {
      key: 'reasoning',
      label: 'Reasoning',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.message || 'AI detection: suspicious activity'}</div>
          <div className="nv-table__meta">
            {row.breakdown?.reasons?.slice(0, 2)?.join(' | ')
              || row.breakdown?.primary_detection
              || row.severity
              || 'Threat intelligence match'}
          </div>
        </>
      ),
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (row) => <StatusBadge tone={getRiskTone(row.severity)}>{row.severity}</StatusBadge>,
    },
  ];

  if (error && !loading && threats.length === 0) {
    return (
      <div className="nv-page">
        <ErrorState title="Threat Telemetry Error" message={error} onRetry={() => fetchThreats()} />
      </div>
    );
  }

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Investigation"
        title="Threat Investigation"
        description="Prioritize high-risk detections, inspect the target and reasoning behind each alert, and keep the threat queue readable instead of visually noisy."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchThreats()}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard icon="ri-shield-flash-line" label="Active Threats" value={threatCount} meta="Open high and critical detections" accent="#fb7185" />
        <MetricCard icon="ri-alarm-warning-line" label="Critical" value={criticalCount} meta="Priority incidents requiring fastest triage" accent="#f97316" />
        <MetricCard icon="ri-focus-3-line" label="Queue State" value={threats.length > 0 ? 'Attention' : 'Quiet'} meta={`Top signal: ${topReason[0]}`} accent="#2dd4bf" />
      </div>

      <SectionCard title="Threat Queue" caption="Table-first Investigation">
        {loading ? (
          <TableSkeleton rows={6} />
        ) : (
          <DataTable
            columns={threatColumns}
            rows={threats}
            rowKey={(row, index) => row.id || row.flow_id || `${row.timestamp}-${index}`}
            onRowClick={(row) => setSelectedThreat(row)}
            emptyTitle="No high-risk threats detected"
            emptyDescription="The high-severity queue is currently quiet. Continue monitoring the live feeds for new detections."
          />
        )}
      </SectionCard>

      <ThreatDrawer
        open={Boolean(selectedThreat)}
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        title="Threat Audit Details"
      />
    </div>
  );
};

export default ThreatsPage;

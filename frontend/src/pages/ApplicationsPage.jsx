import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { useWebSocket } from '../hooks/useWebSocket';
import { formatRuntime, getApplicationVisual, isNetworkServiceApplication } from '../utils/apps';
import { formatByteCount } from '../utils/presentation';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import StatusBadge from '../components/V2/StatusBadge';
import DataTable from '../components/V2/DataTable';
import GlassModal from '../components/V2/GlassModal';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

const parseByteValue = (value) => {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value !== 'string') {
    return 0;
  }

  const match = value.trim().match(/^([\d.]+)\s*(B|KB|MB|GB)?$/i);
  if (!match) {
    const fallback = Number.parseFloat(value);
    return Number.isFinite(fallback) ? fallback : 0;
  }

  const amount = Number.parseFloat(match[1]);
  const unit = (match[2] || 'B').toUpperCase();
  const scale = {
    B: 1,
    KB: 1024,
    MB: 1024 * 1024,
    GB: 1024 * 1024 * 1024,
  };
  return Math.round(amount * (scale[unit] || 1));
};

const sortApplications = (entries) => [...entries].sort((left, right) => (
  (right.live_event_count || 0) - (left.live_event_count || 0)
  || (right.active_device_count || 0) - (left.active_device_count || 0)
  || (right.bandwidth_bytes || 0) - (left.bandwidth_bytes || 0)
  || String(left.application).localeCompare(String(right.application))
));

const appKindLabel = (application) => (
  isNetworkServiceApplication(application) ? 'Network service' : 'Product app'
);

const compactHost = (host) => {
  const value = String(host || '').trim();
  if (!value) return '';
  return value.length > 28 ? `${value.slice(0, 25)}...` : value;
};

const appDetectionSummary = (app) => {
  if (isNetworkServiceApplication(app.application)) {
    return 'Protocol bucket';
  }
  if (app.live_domain) {
    return `Live: ${compactHost(app.live_domain)}`;
  }
  if (app.top_domain) {
    return `Domain: ${compactHost(app.top_domain)}`;
  }
  return 'Dynamic Intelligence';
};

const appActivitySummary = (app) => {
  const activeNow = app.live_event_count || app.active_device_count || 0;
  if (activeNow > 0) {
    return `${activeNow} live signal${activeNow === 1 ? '' : 's'} right now`;
  }
  if (app.last_seen) {
    return `Last observed ${app.last_seen}`;
  }
  return 'No live traffic in the current refresh window';
};

const appNextStep = (app) => {
  if (isNetworkServiceApplication(app.application)) {
    return 'Review if high traffic';
  }
  if ((app.live_event_count || 0) > 0) {
    return 'Open device usage';
  }
  return 'Watch history';
};

const ApplicationsPage = () => {
  const navigate = useNavigate();
  const [applications, setApplications] = useState([]);
  const [liveFeed, setLiveFeed] = useState([]);
  const [analytics, setAnalytics] = useState({ uncategorized_domains: [] });
  const [overrides, setOverrides] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState('all'); // 'all' | 'active' | 'product' | 'service'

  // Override Modal state
  const [isOverrideModalOpen, setIsOverrideModalOpen] = useState(false);
  const [overrideDomain, setOverrideDomain] = useState('');
  const [overrideAppName, setOverrideAppName] = useState('');
  const [overrideCategory, setOverrideCategory] = useState('web');
  const [savingOverride, setSavingOverride] = useState(false);
  const [overrideError, setOverrideError] = useState('');

  const fetchApplications = useCallback(async () => {
    try {
      const [summaryRes, activityRes, analyticsRes, overridesRes] = await Promise.all([
        systemService.getAppsSummary(),
        systemService.getActivity(120),
        systemService.getAnalyticsOverview(24, 6),
        systemService.getAppOverrides().catch(() => ({ data: [] })),
      ]);
      setApplications(summaryRes.data || []);
      setLiveFeed(activityRes.data || []);
      setAnalytics(analyticsRes.data || { uncategorized_domains: [] });
      setOverrides(overridesRes.data || []);
    } catch (err) {
      console.error('Failed to fetch applications', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchApplications();
  }, [fetchApplications]);

  useVisibilityPolling(fetchApplications, 5000);

  const handlePacketEvent = useCallback((event) => {
    setLiveFeed((current) => [event, ...current].slice(0, 160));
  }, []);

  useWebSocket('packet_event', handlePacketEvent);

  const liveApplicationMap = useMemo(() => {
    return liveFeed.reduce((acc, entry) => {
      const application = entry.application || 'Other';
      const current = acc.get(application) || {
        event_count: 0,
        device_ips: new Set(),
        bandwidth_bytes: 0,
        last_seen: '',
        top_domain: '',
      };
      current.event_count += 1;
      if (entry.src_ip) {
        current.device_ips.add(entry.src_ip);
      }
      current.bandwidth_bytes += parseByteValue(entry.byte_count ?? entry.size ?? 0);
      current.last_seen = entry.timestamp || entry.time_str || entry.last_seen || current.last_seen;
      current.top_domain = entry.domain || current.top_domain;
      acc.set(application, current);
      return acc;
    }, new Map());
  }, [liveFeed]);

  const mergedApplications = useMemo(() => {
    const merged = new Map(
      applications.map((app) => [
        app.application,
        {
          ...app,
          live_event_count: 0,
          live_device_count: 0,
          live_domain: '',
          live_bandwidth_bytes: 0,
        },
      ]),
    );

    liveApplicationMap.forEach((entry, application) => {
      const existing = merged.get(application);
      if (existing) {
        merged.set(application, {
          ...existing,
          live_event_count: entry.event_count,
          live_device_count: entry.device_ips.size,
          live_domain: entry.top_domain,
          live_bandwidth_bytes: entry.bandwidth_bytes,
        });
        return;
      }

      merged.set(application, {
        application,
        device_count: entry.device_ips.size,
        active_device_count: entry.device_ips.size,
        bandwidth_bytes: entry.bandwidth_bytes,
        bandwidth: formatByteCount(entry.bandwidth_bytes),
        runtime_seconds: 0,
        runtime: 'Live now',
        last_seen: entry.last_seen || 'N/A',
        live_event_count: entry.event_count,
        live_device_count: entry.device_ips.size,
        live_domain: entry.top_domain,
        live_bandwidth_bytes: entry.bandwidth_bytes,
      });
    });

    return Array.from(merged.values()).sort((left, right) => (
      (isNetworkServiceApplication(left.application) ? 1 : 0) - (isNetworkServiceApplication(right.application) ? 1 : 0)
      || (right.live_event_count || 0) - (left.live_event_count || 0)
      || (right.active_device_count || 0) - (left.active_device_count || 0)
      || (right.bandwidth_bytes || 0) - (left.bandwidth_bytes || 0)
      || String(left.application).localeCompare(String(right.application))
    ));
  }, [applications, liveApplicationMap]);

  const filteredApplications = useMemo(() => {
    let list = mergedApplications;
    const query = searchQuery.trim().toLowerCase();
    if (query) {
      list = list.filter((app) =>
        app.application.toLowerCase().includes(query) ||
        (app.live_domain && app.live_domain.toLowerCase().includes(query)) ||
        (app.top_domain && app.top_domain.toLowerCase().includes(query))
      );
    }
    if (filterMode === 'active') {
      list = list.filter((app) => (app.live_event_count || 0) > 0 || (app.active_device_count || 0) > 0);
    } else if (filterMode === 'product') {
      list = list.filter((app) => !isNetworkServiceApplication(app.application));
    } else if (filterMode === 'service') {
      list = list.filter((app) => isNetworkServiceApplication(app.application));
    }
    return list;
  }, [mergedApplications, searchQuery, filterMode]);

  const { productApplications, networkApplications } = useMemo(() => {
    const products = [];
    const services = [];
    filteredApplications.forEach((app) => {
      if (isNetworkServiceApplication(app.application)) {
        services.push(app);
      } else {
        products.push(app);
      }
    });

    return {
      productApplications: sortApplications(products),
      networkApplications: sortApplications(services),
    };
  }, [filteredApplications]);

  const classificationRows = useMemo(() => analytics.uncategorized_domains || [], [analytics]);

  const totals = useMemo(() => {
    return mergedApplications.reduce(
      (acc, app) => {
        const isService = isNetworkServiceApplication(app.application);
        const isActive = (app.live_event_count || 0) > 0 || (app.active_device_count || 0) > 0;
        acc.deviceCount += app.device_count || 0;
        acc.bandwidthBytes += app.bandwidth_bytes || 0;
        if (isService) {
          acc.networkServices += 1;
          if (isActive) {
            acc.activeNetworkServices += 1;
          }
        } else {
          acc.productApps += 1;
          if (isActive) {
            acc.activeProductApps += 1;
          }
        }
        return acc;
      },
      {
        deviceCount: 0,
        bandwidthBytes: 0,
        productApps: 0,
        networkServices: 0,
        activeProductApps: 0,
        activeNetworkServices: 0,
      },
    );
  }, [mergedApplications]);

  const pageInsights = useMemo(() => {
    const topProduct = productApplications[0];
    const topService = networkApplications[0];
    const liveEvents = mergedApplications.reduce((sum, app) => sum + (app.live_event_count || 0), 0);
    const dominantApp = topProduct || topService;
    return {
      liveEvents,
      dominantCopy: dominantApp
        ? `${dominantApp.application} is the clearest active signal${dominantApp.live_domain ? ` via ${dominantApp.live_domain}` : ''}.`
        : 'No application signal is active yet.',
      productCopy: `${totals.productApps} named product app${totals.productApps === 1 ? '' : 's'} dynamically detected.`,
      serviceCopy: `${totals.networkServices} network service bucket${totals.networkServices === 1 ? '' : 's'} kept apart for cleaner reading.`,
      classificationCopy: classificationRows.length > 0
        ? `${classificationRows.length} host${classificationRows.length === 1 ? '' : 's'} still need app mapping.`
        : 'No major classification gaps in the current window.',
    };
  }, [classificationRows.length, mergedApplications, networkApplications, productApplications, totals]);

  const handleOpenOverrideModal = (domainToPin = '') => {
    setOverrideDomain(domainToPin);
    setOverrideAppName('');
    setOverrideCategory('web');
    setOverrideError('');
    setIsOverrideModalOpen(true);
  };

  const handleSaveOverride = async () => {
    if (!overrideDomain.trim() || !overrideAppName.trim()) {
      setOverrideError('Domain and application name are required.');
      return;
    }
    setSavingOverride(true);
    setOverrideError('');
    try {
      await systemService.setAppOverride({
        domain: overrideDomain.trim(),
        application_name: overrideAppName.trim(),
        category: overrideCategory,
      });
      setIsOverrideModalOpen(false);
      await fetchApplications();
    } catch (err) {
      setOverrideError(err.response?.data?.detail || 'Failed to save application override.');
    } finally {
      setSavingOverride(false);
    }
  };

  const handleDeleteOverride = async (domain) => {
    try {
      await systemService.deleteAppOverride(domain);
      await fetchApplications();
    } catch (err) {
      console.error('Failed to delete override', err);
    }
  };

  const renderApplicationGrid = (entries, emptyTitle, emptyDescription) => {
    if (entries.length === 0) {
      return (
        <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0', padding: 0 }}>
          <div className="nv-empty__icon">
            <i className="ri-apps-line"></i>
          </div>
          <div className="nv-stack" style={{ gap: '0.5rem' }}>
            <h3 className="nv-empty__title">{emptyTitle}</h3>
            <p className="nv-empty__description">{emptyDescription}</p>
          </div>
        </div>
      );
    }

    return (
      <div className="nv-card-grid">
        {entries.map((app) => {
          const visual = getApplicationVisual(app.application);
          const isLive = (app.live_event_count || 0) > 0 || (app.active_device_count || 0) > 0;
          return (
            <button
              key={app.application}
              type="button"
              className="nv-card-button nv-app-card"
              onClick={() => navigate(`/apps/${encodeURIComponent(app.application)}`)}
              style={{ '--nv-app-accent': visual.accent }}
            >
              <div className="nv-card-button__header">
                <div className="nv-pill-card" style={{ padding: 0, border: '0', background: 'transparent' }}>
                  <div className="nv-pill-card__icon" style={{ color: visual.accent, background: visual.background, borderColor: `${visual.accent}33` }}>
                    <i className={visual.icon}></i>
                  </div>
                  <div className="nv-pill-card__content">
                    <strong>{app.application}</strong>
                    <span>{app.device_count} device{app.device_count === 1 ? '' : 's'} in 24h window</span>
                  </div>
                </div>
                <StatusBadge tone={isLive ? 'success' : 'neutral'}>
                  {isLive ? 'Active' : 'Idle'}
                </StatusBadge>
              </div>
              <div className="nv-card-button__value">{app.bandwidth || formatByteCount(app.bandwidth_bytes)}</div>
              <div className="nv-card-button__footer">
                <span>{app.live_event_count || app.active_device_count || 0} active now</span>
                <span>{app.runtime || formatRuntime(app.runtime_seconds)}</span>
              </div>
              <div className="nv-app-card__explain">
                <div>
                  <span>Meaning</span>
                  <strong>{appKindLabel(app.application)}</strong>
                </div>
                <div>
                  <span>Detection</span>
                  <strong>{appDetectionSummary(app)}</strong>
                </div>
                <div>
                  <span>Next step</span>
                  <strong>{appNextStep(app)}</strong>
                </div>
              </div>
              <p className="nv-app-card__summary">{appActivitySummary(app)}</p>
            </button>
          );
        })}
      </div>
    );
  };

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Inventory"
        title="Application Coverage"
        description="Dynamic 5-layer classification detects running apps, PaaS services, and browser activity without hardcoded dictionary limits."
        actions={(
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="nv-button nv-button--secondary"
              onClick={() => handleOpenOverrideModal()}
            >
              <i className="ri-edit-line"></i>
              Manage Overrides
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={fetchApplications}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </div>
        )}
      />

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard
            icon="ri-apps-2-line"
            label="Visible Apps"
            value={mergedApplications.length}
            meta={`${totals.deviceCount} device associations | ${totals.productApps} product apps | ${totals.networkServices} service buckets`}
            accent="#54c8e8"
          />
          <MetricCard
            icon="ri-flashlight-line"
            label="Active Product Apps"
            value={totals.activeProductApps}
            meta={`${totals.activeNetworkServices} service buckets are active in the live feed`}
            accent="#22d3ee"
          />
          <MetricCard
            icon="ri-radar-line"
            label="Network Services"
            value={totals.networkServices}
            meta="Transport and control-plane buckets are grouped separately"
            accent="#8b5cf6"
          />
          <MetricCard
            icon="ri-exchange-funds-line"
            label="Traffic Volume"
            value={formatByteCount(totals.bandwidthBytes)}
            meta="Aggregated across the 24-hour application window"
            accent="#2dd4bf"
          />
        </div>
      )}

      {/* Filter and Search Bar */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', justifyContent: 'space-between', margin: '1rem 0' }}>
        <div style={{ display: 'flex', gap: '0.5rem', flex: '1 1 240px', maxWidth: '380px' }}>
          <div className="nv-search-field" style={{ width: '100%', position: 'relative' }}>
            <i className="ri-search-line" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', opacity: 0.6 }}></i>
            <input
              type="text"
              className="nv-input"
              style={{ paddingLeft: '2.25rem', width: '100%' }}
              placeholder="Search applications or domains..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.375rem' }}>
          {[
            { id: 'all', label: `All (${mergedApplications.length})` },
            { id: 'active', label: `Active (${totals.activeProductApps + totals.activeNetworkServices})` },
            { id: 'product', label: `Products (${totals.productApps})` },
            { id: 'service', label: `Services (${totals.networkServices})` },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              className={`nv-button nv-button--sm ${filterMode === tab.id ? 'nv-button--primary' : 'nv-button--ghost'}`}
              onClick={() => setFilterMode(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {!loading ? (
        <SectionCard title="Application Understanding" caption="Plain-language Readout" className="nv-section--clarity">
          <div className="nv-app-brief">
            <div className="nv-app-brief__lead">
              <span className="nv-app-brief__icon">
                <i className="ri-apps-2-add-line"></i>
              </span>
              <div>
                <h2>{pageInsights.dominantCopy}</h2>
                <p>NetVisor dynamically analyzes page metadata, multi-tenant subdomains, and traffic telemetry to name active tools automatically.</p>
              </div>
            </div>
            <div className="nv-app-brief__cards">
              <div className="nv-mini-explainer">
                <span>Named apps</span>
                <strong>{pageInsights.productCopy}</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Services</span>
                <strong>{pageInsights.serviceCopy}</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Live feed</span>
                <strong>{pageInsights.liveEvents} fresh packet signal{pageInsights.liveEvents === 1 ? '' : 's'} in memory.</strong>
              </div>
              <div className="nv-mini-explainer">
                <span>Classification</span>
                <strong>{pageInsights.classificationCopy}</strong>
              </div>
            </div>
          </div>
        </SectionCard>
      ) : null}

      {(filterMode === 'all' || filterMode === 'product' || filterMode === 'active') && (
        <SectionCard title="Product Apps" caption="Dynamically identified apps with concrete brand identity">
          {loading ? (
            <TableSkeleton rows={4} />
          ) : (
            renderApplicationGrid(
              productApplications,
              'No matching product applications',
              'No product applications match your search or active filter.',
            )
          )}
        </SectionCard>
      )}

      {(filterMode === 'all' || filterMode === 'service' || filterMode === 'active') && (
        <SectionCard
          title="Network Services"
          caption="Transport, control, and unclassified buckets shown apart from product apps"
        >
          {loading ? (
            <TableSkeleton rows={4} />
          ) : (
            renderApplicationGrid(
              networkApplications,
              'No matching network services',
              'Protocol-level buckets such as HTTPS, DNS, QUIC, NBNS, Other, and Unknown will appear here when active.',
            )
          )}
        </SectionCard>
      )}

      <SectionCard
        title="Needs Classification"
        caption="Known hosts that are still rolling up as Other or Unknown"
        aside={<StatusBadge tone="warning">{classificationRows.length} hosts</StatusBadge>}
      >
        <div className="nv-scroll-region nv-scroll-region--lg">
          <DataTable
            columns={[
              {
                key: 'host',
                label: 'Host',
                render: (row) => (
                  <>
                    <div className="nv-table__primary">{row.base_domain || row.host || '-'}</div>
                    <div className="nv-table__meta mono">{row.host || '-'}</div>
                  </>
                ),
              },
              {
                key: 'flow_count',
                label: 'Flows',
                render: (row) => <span className="mono">{row.flow_count || 0}</span>,
              },
              {
                key: 'bandwidth',
                label: 'Bandwidth',
                render: (row) => <span className="mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes || 0)}</span>,
              },
              {
                key: 'last_seen',
                label: 'Last Seen',
                render: (row) => <span className="mono">{row.last_seen || 'N/A'}</span>,
              },
              {
                key: 'actions',
                label: 'Actions',
                render: (row) => (
                  <button
                    type="button"
                    className="nv-button nv-button--sm nv-button--secondary"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleOpenOverrideModal(row.base_domain || row.host);
                    }}
                  >
                    <i className="ri-price-tag-3-line"></i>
                    Pin Name
                  </button>
                ),
              },
            ]}
            rows={classificationRows}
            rowKey={(row, index) => `${row.base_domain || row.host || 'unknown'}-${index}`}
            emptyTitle="No classification gaps"
            emptyDescription="The current 24-hour window does not have enough uncategorized hosts to surface here."
          />
        </div>
      </SectionCard>

      {/* Admin Application Override Modal */}
      <GlassModal
        open={isOverrideModalOpen}
        title="Application Identity Overrides"
        description="Pin custom application names and categories for domains. Overrides take immediate precedence over dynamic classifier heuristics."
        confirmText={savingOverride ? 'Saving...' : 'Save Override'}
        cancelText="Close"
        onConfirm={handleSaveOverride}
        onCancel={() => setIsOverrideModalOpen(false)}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '0.5rem' }}>
          {overrideError && (
            <div style={{ color: '#ef4444', fontSize: '0.85rem', background: 'rgba(239, 68, 68, 0.1)', padding: '0.5rem 0.75rem', borderRadius: '4px' }}>
              {overrideError}
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.25rem' }}>
              Domain or Hostname
            </label>
            <input
              type="text"
              className="nv-input"
              style={{ width: '100%' }}
              placeholder="e.g. app.custom-crm.internal or vercel.app"
              value={overrideDomain}
              onChange={(e) => setOverrideDomain(e.target.value)}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.25rem' }}>
              Application Name
            </label>
            <input
              type="text"
              className="nv-input"
              style={{ width: '100%' }}
              placeholder="e.g. SalesForge CRM"
              value={overrideAppName}
              onChange={(e) => setOverrideAppName(e.target.value)}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.25rem' }}>
              Category
            </label>
            <select
              className="nv-input"
              style={{ width: '100%' }}
              value={overrideCategory}
              onChange={(e) => setOverrideCategory(e.target.value)}
            >
              <option value="ai">AI / LLM</option>
              <option value="dev">Developer Tool</option>
              <option value="chat">Chat / Collaboration</option>
              <option value="cloud">Cloud / Infrastructure</option>
              <option value="web">Web Application</option>
              <option value="security">Security / Auth</option>
              <option value="streaming">Media / Streaming</option>
            </select>
          </div>

          {overrides.length > 0 && (
            <div style={{ marginTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '0.75rem' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.5rem', opacity: 0.8 }}>
                Existing Custom Overrides ({overrides.length})
              </div>
              <div style={{ maxHeight: '140px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                {overrides.map((ov) => (
                  <div
                    key={ov.id || ov.domain}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '0.35rem 0.6rem',
                      background: 'rgba(255,255,255,0.03)',
                      borderRadius: '4px',
                      fontSize: '0.8rem',
                    }}
                  >
                    <div>
                      <strong style={{ marginRight: '0.5rem' }}>{ov.application_name}</strong>
                      <span className="mono" style={{ opacity: 0.6 }}>{ov.domain}</span>
                    </div>
                    <button
                      type="button"
                      className="nv-button nv-button--ghost nv-button--sm"
                      style={{ color: '#ef4444', padding: '0.2rem 0.4rem' }}
                      onClick={() => handleDeleteOverride(ov.domain)}
                      title="Remove override"
                    >
                      <i className="ri-delete-bin-line"></i>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </GlassModal>
    </div>
  );
};

export default ApplicationsPage;


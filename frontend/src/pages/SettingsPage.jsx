import { useCallback, useEffect, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import StatusBadge from '../components/V2/StatusBadge';
import Switch from '../components/V2/Switch';
import GlassModal from '../components/V2/GlassModal';
import { getSoundStatus, toggleSound, playSuccessSound } from '../utils/sound';
import { useImmersion } from '../immersion/engine/useImmersion';

const SettingsPage = () => {
  const [stats, setStats] = useState({ cpu_percent: 0, mem_used_mb: 0, mem_total_mb: 1024, maintenance_mode: false });
  const [systemActive, setSystemActive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [soundEnabled, setSoundEnabled] = useState(() => getSoundStatus());
  
  const {
    animationsEnabled,
    setAnimationsEnabled,
    enhancedEffectsEnabled,
    setEnhancedEffectsEnabled,
    ambientEffectsEnabled,
    setAmbientEffectsEnabled
  } = useImmersion();
  
  const [modalConfig, setModalConfig] = useState({
    open: false,
    title: '',
    description: '',
    confirmText: 'Dismiss',
    cancelText: 'Cancel',
    onConfirm: null,
    onCancel: null,
    variant: 'alert'
  });

  const showAlert = (title, description) => {
    setModalConfig({
      open: true,
      title,
      description,
      confirmText: 'Dismiss',
      cancelText: '',
      onConfirm: () => setModalConfig(prev => ({ ...prev, open: false })),
      onCancel: () => setModalConfig(prev => ({ ...prev, open: false })),
      variant: 'alert'
    });
  };

  const showConfirm = (title, description, onConfirm) => {
    setModalConfig({
      open: true,
      title,
      description,
      confirmText: 'Reset Database',
      cancelText: 'Cancel',
      onConfirm: () => {
        setModalConfig(prev => ({ ...prev, open: false }));
        onConfirm();
      },
      onCancel: () => setModalConfig(prev => ({ ...prev, open: false })),
      variant: 'danger'
    });
  };

  const handleToggleSound = () => {
    const newVal = toggleSound();
    setSoundEnabled(newVal);
    if (newVal) {
      setTimeout(() => {
        playSuccessSound();
      }, 50);
    }
  };

  const fetchData = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const [statsRes, sysRes] = await Promise.all([
        systemService.getAdminStats(),
        systemService.getSystemStatus(),
      ]);
      setStats(statsRes.data || { cpu_percent: 0, mem_used_mb: 0, mem_total_mb: 1024, maintenance_mode: false });
      setSystemActive(Boolean(sysRes.data?.runtime?.active ?? sysRes.data?.active));
    } catch (err) {
      console.error('Failed to fetch settings data', err);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useVisibilityPolling(() => fetchData({ background: true }), 20000);

  const toggleMaintenance = async () => {
    try {
      await systemService.setMaintenanceMode(!stats.maintenance_mode);
      await fetchData();
    } catch {
      showAlert('Operation Failed', 'Failed to toggle maintenance mode. Verify backend service connection.');
    }
  };

  const toggleMonitoring = async () => {
    try {
      await systemService.setMonitoring(!systemActive);
      await fetchData();
    } catch {
      showAlert('Operation Failed', 'Failed to toggle monitoring. Verify engine control access.');
    }
  };

  const triggerScan = async () => {
    try {
      const res = await systemService.triggerScan();
      showAlert('Scan Triggered', res.data.message || 'Discovery and segment scan successfully initiated.');
    } catch {
      showAlert('Scan Failed', 'Failed to force network scan. Anomaly engine might be offline.');
    }
  };

  const resetDatabase = () => {
    showConfirm(
      'Critical Database Reset',
      'This will wipe all traffic logs, security alerts, and system telemetry history. Active analyst profiles and system configuration will be preserved. This operation is permanent.',
      async () => {
        try {
          const res = await systemService.resetDatabase();
          showAlert('Database Purged', res.data.message || 'All traffic tables wiped successfully.');
          setTimeout(() => {
            window.location.reload();
          }, 2000);
        } catch {
          showAlert('Reset Failed', 'Failed to purge database tables. Database session might be locked.');
        }
      }
    );
  };

  const memoryPercent = stats.mem_total_mb > 0 
    ? Math.round((stats.mem_used_mb / stats.mem_total_mb) * 100) 
    : 0;

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Operations"
        title="System Controls"
        description="Group runtime controls, inspection posture, operational actions, and dangerous resets into one structured administration surface."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchData()}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard 
          icon="ri-cpu-line" 
          label="CPU Load" 
          value={`${Math.round(stats.cpu_percent || 0)}%`} 
          meta="Server CPU load" 
          accent="#54c8e8" 
          progress={Math.round(stats.cpu_percent || 0)}
        />
        <MetricCard 
          icon="ri-database-2-line" 
          label="Memory" 
          value={`${(stats.mem_used_mb / 1024).toFixed(1)} GB`} 
          meta={`${memoryPercent}% of ${(stats.mem_total_mb / 1024).toFixed(1)} GB total`} 
          accent="#60a5fa" 
          progress={memoryPercent}
        />
        <MetricCard 
          icon="ri-radar-line" 
          label="Monitoring" 
          value={systemActive ? 'Active' : 'Paused'} 
          meta="Packet and activity collection" 
          accent="#2dd4bf" 
        />
        <MetricCard 
          icon="ri-tools-line" 
          label="Maintenance" 
          value={stats.maintenance_mode ? 'Enabled' : 'Disabled'} 
          meta="Restricted access mode" 
          accent="#fbbf24" 
        />
      </div>

      {!loading ? (
        <div className="nv-grid nv-grid--three">
          <SectionCard title="System Controls" caption="Runtime">
            <div className="nv-inline-actions" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div className="nv-table__primary">Monitoring Engine</div>
                <div className="nv-table__meta">{systemActive ? 'Capturing and classifying traffic' : 'Collection paused'}</div>
              </div>
              <Switch checked={systemActive} onChange={toggleMonitoring} />
            </div>
            
            <div className="nv-inline-actions" style={{ justifyContent: 'space-between', alignItems: 'center', marginTop: '1.2rem' }}>
              <div>
                <div className="nv-table__primary">Maintenance Mode</div>
                <div className="nv-table__meta">{stats.maintenance_mode ? 'Restricted access and controlled changes' : 'Normal access'}</div>
              </div>
              <Switch checked={stats.maintenance_mode} onChange={toggleMaintenance} />
            </div>
          </SectionCard>

          <SectionCard title="Operational Actions" caption="Safe Actions">
            <div className="nv-stack" style={{ gap: '1.2rem' }}>
              <div className="nv-inline-actions" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="nv-table__primary">Force Network Scan</div>
                  <div className="nv-table__meta">Scan active network segments</div>
                </div>
                <button type="button" className="nv-button nv-button--secondary" onClick={triggerScan}>
                  <i className="ri-radar-line"></i>
                  Scan
                </button>
              </div>

              <div className="nv-inline-actions" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="nv-table__primary">UI Sound Effects</div>
                  <div className="nv-table__meta">Play chimes and click sounds</div>
                </div>
                <Switch checked={soundEnabled} onChange={handleToggleSound} />
              </div>

              <div className="nv-inline-actions" style={{ marginTop: '0.45rem' }}>
                <StatusBadge tone="accent" icon="ri-shield-check-line">Runtime healthy</StatusBadge>
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Visual Fidelity" caption="Theme Effects">
            <div className="nv-stack" style={{ gap: '1.2rem' }}>
              <div className="nv-inline-actions" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="nv-table__primary">Animations</div>
                  <div className="nv-table__meta">Enable transitions, glitches, and pulses</div>
                </div>
                <Switch checked={animationsEnabled} onChange={() => setAnimationsEnabled(!animationsEnabled)} />
              </div>

              <div className="nv-inline-actions" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="nv-table__primary">Enhanced Effects</div>
                  <div className="nv-table__meta">Enable card scanlines, glows, and sweeps</div>
                </div>
                <Switch checked={enhancedEffectsEnabled} onChange={() => setEnhancedEffectsEnabled(!enhancedEffectsEnabled)} />
              </div>

              <div className="nv-inline-actions" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="nv-table__primary">Ambient Effects</div>
                  <div className="nv-table__meta">Enable background rain, particles, and grids</div>
                </div>
                <Switch checked={ambientEffectsEnabled} onChange={() => setAmbientEffectsEnabled(!ambientEffectsEnabled)} />
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Danger Zone" caption="Destructive Actions">
            <div className="nv-danger-panel">
              <p>Resetting the runtime database clears traffic logs, flow histories, and alerts while preserving analyst users. Use only when you want a clean audit window.</p>
              <button 
                type="button" 
                className="nv-button nv-button--danger" 
                onClick={resetDatabase}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <i className="ri-delete-bin-2-line"></i>
                Reset Database
              </button>
            </div>
          </SectionCard>
        </div>
      ) : null}

      <GlassModal {...modalConfig} />
    </div>
  );
};

export default SettingsPage;

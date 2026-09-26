import React, { useEffect, useState } from 'react';
import SidePanel from '../Common/SidePanel';
import StatusBadge from '../Common/StatusBadge';
import { systemService } from '../../services/api';
import { formatByteCount, formatPercent, getRiskTone, getStatusTone } from '../../utils/presentation';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { getApplicationVisual } from '../../utils/apps';

export const DeviceDetailsPanel = ({ deviceIp, open, onClose }) => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!deviceIp || !open) {
      setProfile(null);
      return;
    }

    let isMounted = true;
    setLoading(true);
    setError(null);

    systemService
      .getDeviceProfile(deviceIp)
      .then((res) => {
        if (isMounted) {
          setProfile(res.data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.error('Failed to load device profile', err);
          setError('Failed to load device details from gateway');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [deviceIp, open]);

  const device = profile?.device || {};
  const riskTone = getRiskTone(profile?.risk_level || device?.risk_level);
  const statusTone = getStatusTone(profile?.status || device?.status);

  return (
    <SidePanel
      open={open}
      onClose={onClose}
      title={profile?.hostname || (deviceIp ? `Device ${deviceIp}` : 'Asset Diagnostics')}
      description={`Endpoint ${deviceIp} · Inspection Profile & Telemetry`}
      width="max-w-2xl"
    >
      {loading ? (
        <div className="space-y-4 py-8">
          <div className="h-20 bg-white/5 rounded-xl animate-pulse" />
          <div className="h-32 bg-white/5 rounded-xl animate-pulse" />
          <div className="h-40 bg-white/5 rounded-xl animate-pulse" />
        </div>
      ) : error ? (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm">
          {error}
        </div>
      ) : profile ? (
        <div className="space-y-6">
          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/5">
              <span className="text-[10.5px] uppercase tracking-wider text-[#9AA3B8] font-semibold block mb-1">
                Status
              </span>
              <StatusBadge tone={statusTone}>{profile.status || 'Active'}</StatusBadge>
            </div>
            <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/5">
              <span className="text-[10.5px] uppercase tracking-wider text-[#9AA3B8] font-semibold block mb-1">
                Risk Score
              </span>
              <span className="text-base font-extrabold tabular-nums" style={{ color: riskTone === 'danger' ? '#FB7185' : riskTone === 'warning' ? '#F59E0B' : '#34D399' }}>
                {profile.risk_score || 0}%
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/5">
              <span className="text-[10.5px] uppercase tracking-wider text-[#9AA3B8] font-semibold block mb-1">
                Mode
              </span>
              <span className="text-xs font-semibold text-[#F1F3F9] uppercase">
                {profile.management_mode || 'BYOD'}
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/5">
              <span className="text-[10.5px] uppercase tracking-wider text-[#9AA3B8] font-semibold block mb-1">
                Bandwidth
              </span>
              <span className="text-xs font-bold mono text-[#54C8E8]">
                {profile.bandwidth || '0 B'}
              </span>
            </div>
          </div>

          {/* Identity & Hardware Card */}
          <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#9AA3B8]">
              Device Identity & Fingerprint
            </h4>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-[#5E6579] block">IP Address:</span>
                <span className="mono font-semibold text-[#F1F3F9]">{deviceIp}</span>
              </div>
              <div>
                <span className="text-[#5E6579] block">MAC Address:</span>
                <span className="mono font-semibold text-[#F1F3F9]">{device.mac || '-'}</span>
              </div>
              <div>
                <span className="text-[#5E6579] block">Vendor:</span>
                <span className="text-[#F1F3F9]">{device.vendor || 'Unknown Hardware'}</span>
              </div>
              <div>
                <span className="text-[#5E6579] block">OS / Device Type:</span>
                <span className="text-[#F1F3F9]">
                  {[device.os_family, device.device_type].filter(Boolean).join(' · ') || 'Unclassified'}
                </span>
              </div>
              <div>
                <span className="text-[#5E6579] block">First Seen:</span>
                <span className="text-[#F1F3F9]">{formatUtcTimestampToLocal(device.first_seen)}</span>
              </div>
              <div>
                <span className="text-[#5E6579] block">Last Seen:</span>
                <span className="text-[#F1F3F9]">{formatUtcTimestampToLocal(profile.last_seen)}</span>
              </div>
            </div>
          </div>

          {/* Top Applications Breakdown */}
          {profile.applications?.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#9AA3B8]">
                Observed Applications ({profile.applications.length})
              </h4>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {profile.applications.slice(0, 6).map((app, idx) => {
                  const visual = getApplicationVisual(app.application);
                  return (
                    <div
                      key={idx}
                      className="p-2.5 px-3 rounded-lg bg-white/[0.02] border border-white/5 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="flex items-center gap-2.5">
                        <div
                          className="w-6 h-6 rounded-md flex items-center justify-center shrink-0"
                          style={{ backgroundColor: visual.background, color: visual.accent }}
                        >
                          <i className={`${visual.icon} text-xs`}></i>
                        </div>
                        <span className="font-semibold text-[#F1F3F9]">{app.application}</span>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className="text-[#9AA3B8]">{app.event_count} sessions</span>
                        <span className="mono font-bold text-[#60A5FA]">{app.bandwidth}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recent Connection Events */}
          {profile.recent_events?.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#9AA3B8]">
                Recent Sessions
              </h4>
              <div className="space-y-2">
                {profile.recent_events.slice(0, 5).map((evt, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 px-3 rounded-lg bg-white/[0.02] border border-white/5 flex items-center justify-between text-xs"
                  >
                    <div className="space-y-0.5">
                      <div className="font-semibold text-[#F1F3F9]">
                        {evt.application || 'Network Socket'}
                      </div>
                      <div className="mono text-[11px] text-[#9AA3B8]">
                        {evt.dst_ip}:{evt.dst_port || 443} {evt.domain ? `(${evt.domain})` : ''}
                      </div>
                    </div>
                    <div className="text-right space-y-0.5">
                      <span className="mono text-[#54C8E8] font-bold block">
                        {formatByteCount(evt.size || evt.byte_count || 0)}
                      </span>
                      <span className="text-[10.5px] text-[#5E6579]">
                        {formatUtcTimestampToLocal(evt.timestamp || evt.last_seen)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="text-center py-12 text-[#9AA3B8] text-sm">
          No endpoint telemetry selected.
        </div>
      )}
    </SidePanel>
  );
};

export default DeviceDetailsPanel;

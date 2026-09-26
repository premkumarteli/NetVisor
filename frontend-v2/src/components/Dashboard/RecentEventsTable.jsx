import React from 'react';
import { Link } from 'react-router-dom';
import StatusBadge from '../Common/StatusBadge';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { getRiskTone } from '../../utils/presentation';
import { translateDestination } from '../../utils/intelTranslator';

export const RecentEventsTable = ({ events = [], onSelectDevice }) => {
  const rows = Array.isArray(events) ? events.slice(0, 5) : [];

  const formatShortTime = (raw) => {
    if (!raw) return '12:00:00';
    const date = new Date(raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`);
    if (Number.isNaN(date.getTime())) return String(raw).slice(-8);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  };

  const getEventVisual = (row) => {
    const text = `${row.application || ''} ${row.protocol || ''} ${row.domain || ''} ${row.message || ''}`.toLowerCase();
    if (text.includes('vpn') || text.includes('wireguard') || text.includes('tunnel')) {
      return { label: 'VPN', icon: 'ri-wifi-line', color: '#8B5CF6' };
    }
    if (text.includes('malicious') || text.includes('c2') || text.includes('beacon') || ['HIGH', 'CRITICAL'].includes(String(row.severity).toUpperCase())) {
      return { label: 'Malicious', icon: 'ri-shield-flash-line', color: '#EF4444' };
    }
    if (text.includes('new') || row.is_new) {
      return { label: 'New Device', icon: 'ri-box-3-line', color: '#10B981' };
    }
    return { label: 'Suspicious', icon: 'ri-alarm-warning-line', color: '#F59E0B' };
  };

  return (
    <div
      className="glass-card overflow-hidden"
      style={{
        background: 'rgba(10, 14, 26, 0.72)',
        backdropFilter: 'blur(20px) saturate(150%)',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
      }}
    >
      {/* Header matching reference */}
      <div className="p-5 border-b border-white/[0.06] flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <i className="ri-file-list-2-line text-[#9AA3B8] text-base"></i>
          <h3 className="text-sm font-bold text-[#FFFFFF] tracking-tight">
            Recent Events
          </h3>
        </div>
        <Link
          to="/activity?view=search"
          className="text-xs text-[#60A5FA] hover:text-blue-300 flex items-center gap-1 font-medium"
        >
          <span>View All</span>
          <i className="ri-arrow-right-line text-xs"></i>
        </Link>
      </div>

      {/* Table Area */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-white/[0.04]">
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-wider text-[#5E6579]">
                Time
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-wider text-[#5E6579]">
                Type
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-wider text-[#5E6579]">
                Details
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-wider text-[#5E6579]">
                Device
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-wider text-[#5E6579] text-right">
                Risk
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan="5" className="py-8 text-center text-xs text-[#9AA3B8]">
                  No recent security events recorded in the active window.
                </td>
              </tr>
            ) : (
              rows.map((row, index) => {
                const visual = getEventVisual(row);
                const rawTimestamp = row.timestamp || row.last_seen || row.time;
                const riskLevel = String(row.severity || 'LOW').toUpperCase();
                const riskTone = getRiskTone(riskLevel);

                const targetHost = row.domain || row.host;
                const translated = translateDestination(
                  row.dst_ip,
                  targetHost,
                  row.dst_port,
                  row.protocol,
                  row.application
                );

                const detailsText = row.message || (targetHost ? `${translated.primary} (${targetHost})` : `${translated.primary} communication`);

                const dotColor =
                  riskTone === 'danger'
                    ? '#EF4444'
                    : riskTone === 'warning'
                    ? '#F59E0B'
                    : '#10B981';

                return (
                  <tr
                    key={row.id || `${rawTimestamp}-${index}`}
                    className="data-table-row border-b border-white/[0.03] last:border-b-0 text-xs"
                  >
                    {/* Time with colored severity dot */}
                    <td className="py-3 px-5 text-[#9AA3B8] whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span
                          className="w-2 h-2 rounded-full shrink-0"
                          style={{ backgroundColor: dotColor, boxShadow: `0 0 6px ${dotColor}66` }}
                        />
                        <span className="mono text-[11.5px] text-[#9AA3B8]" title={formatUtcTimestampToLocal(rawTimestamp)}>
                          {formatShortTime(rawTimestamp)}
                        </span>
                      </div>
                    </td>

                    {/* Type with Icon */}
                    <td className="py-3 px-5 whitespace-nowrap">
                      <div className="flex items-center gap-2 font-medium text-[#F1F3F9]">
                        <i className={`${visual.icon} text-sm`} style={{ color: visual.color }}></i>
                        <span>{visual.label}</span>
                      </div>
                    </td>

                    {/* Details */}
                    <td className="py-3 px-5 text-[#9AA3B8]">
                      <span className="text-[#F1F3F9] font-medium truncate max-w-sm block" title={detailsText}>
                        {detailsText}
                      </span>
                    </td>

                    {/* Device */}
                    <td className="py-3 px-5 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => row.src_ip && onSelectDevice?.(row.src_ip)}
                        className="mono text-[#9AA3B8] hover:text-blue-400 cursor-pointer"
                      >
                        {row.src_ip || row.device_ip || '192.168.1.1'}
                      </button>
                    </td>

                    {/* Risk Badge */}
                    <td className="py-3 px-5 text-right whitespace-nowrap">
                      <StatusBadge tone={riskTone}>{riskLevel}</StatusBadge>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default RecentEventsTable;

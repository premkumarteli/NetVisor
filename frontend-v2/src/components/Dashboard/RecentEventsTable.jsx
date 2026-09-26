import React from 'react';
import { Link } from 'react-router-dom';
import StatusBadge from '../Common/StatusBadge';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { formatByteCount, getRiskTone } from '../../utils/presentation';
import { translateDestination, formatRelativeTime } from '../../utils/intelTranslator';

export const RecentEventsTable = ({ events = [], onSelectDevice }) => {
  const rows = Array.isArray(events) ? events.slice(0, 5) : [];

  return (
    <div className="glass-card overflow-hidden">
      {/* Header with Title and "View All" Link */}
      <div className="p-5 border-b border-white/10 flex items-center justify-between">
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-[#9AA3B8]">
            Telemetry Stream
          </span>
          <h3 className="text-base font-bold text-[#F1F3F9] tracking-tight">
            Recent Network Events
          </h3>
        </div>
        <Link
          to="/activity?view=search"
          className="text-xs font-semibold text-[#60A5FA] hover:text-blue-300 transition-colors flex items-center gap-1.5"
        >
          <span>View All in Search Mode</span>
          <i className="ri-arrow-right-line"></i>
        </Link>
      </div>

      {/* Table Area with Flat Dark Background & Locked Row Styling */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-white/10">
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-[0.05em] text-[#9AA3B8]">
                Time
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-[0.05em] text-[#9AA3B8]">
                Type
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-[0.05em] text-[#9AA3B8]">
                Details
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-[0.05em] text-[#9AA3B8]">
                Device / Endpoint
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-[0.05em] text-[#9AA3B8]">
                Risk
              </th>
              <th className="py-3 px-5 text-[10.5px] uppercase font-bold tracking-[0.05em] text-[#9AA3B8] text-right">
                Volume
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan="6" className="py-8 text-center text-xs text-[#9AA3B8]">
                  No recent events recorded in the current telemetry window.
                </td>
              </tr>
            ) : (
              rows.map((row, index) => {
                const targetHost = row.domain || row.host;
                const translated = translateDestination(
                  row.dst_ip,
                  targetHost,
                  row.dst_port,
                  row.protocol,
                  row.application
                );
                const rawTimestamp = row.timestamp || row.last_seen || row.time;
                const riskLevel = String(row.severity || 'LOW').toUpperCase();
                const riskTone = getRiskTone(riskLevel);

                return (
                  <tr
                    key={row.id || `${rawTimestamp}-${index}`}
                    className="data-table-row border-b border-white/[0.04] last:border-b-0"
                  >
                    {/* Time */}
                    <td className="py-3 px-5 text-xs text-[#9AA3B8] whitespace-nowrap">
                      <span className="mono" title={formatUtcTimestampToLocal(rawTimestamp)}>
                        {formatRelativeTime(rawTimestamp)}
                      </span>
                    </td>

                    {/* Type / Application */}
                    <td className="py-3 px-5 text-xs font-semibold text-[#F1F3F9] whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-[#60A5FA]" />
                        <span>{row.application || row.protocol || 'Flow Event'}</span>
                      </div>
                    </td>

                    {/* Details / Destination */}
                    <td className="py-3 px-5 text-xs text-[#F1F3F9]">
                      <div className="truncate max-w-xs" title={targetHost || row.dst_ip}>
                        <span className="text-[#F1F3F9] font-medium">{translated.primary}</span>
                        {translated.meta && (
                          <span className="text-[#5E6579] text-[11px] ml-1.5 mono">
                            {translated.meta}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Device IP */}
                    <td className="py-3 px-5 text-xs whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => row.src_ip && onSelectDevice?.(row.src_ip)}
                        className="mono font-semibold text-[#60A5FA] hover:underline cursor-pointer"
                      >
                        {row.src_ip || row.device_ip || '-'}
                      </button>
                    </td>

                    {/* Risk Badge */}
                    <td className="py-3 px-5 whitespace-nowrap">
                      <StatusBadge tone={riskTone}>{riskLevel}</StatusBadge>
                    </td>

                    {/* Volume */}
                    <td className="py-3 px-5 text-xs text-right whitespace-nowrap">
                      <span className="mono font-bold text-[#54C8E8]">
                        {formatByteCount(row.size || row.byte_count || 0)}
                      </span>
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

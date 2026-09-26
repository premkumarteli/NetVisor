import React, { useMemo } from 'react';
import { formatByteCount } from '../../utils/presentation';

export const TopTalkersCard = ({ topDevices = [], devices = [], onSelectDevice }) => {
  // Aggregate or normalize top talkers list
  const talkers = useMemo(() => {
    let list = [];

    if (Array.isArray(topDevices) && topDevices.length > 0) {
      list = topDevices.map((d) => {
        const ip = d.device_ip || d.ip || 'Unknown';
        const matched = (devices || []).find((dev) => dev.ip === ip);
        return {
          ip,
          hostname: matched?.hostname || d.hostname || `Dev ${ip}`,
          bytes: Number(d.bandwidth_bytes || d.bytes || d.total_bytes || 0),
          connections: Number(d.connection_count || d.flow_count || d.session_count || 1),
        };
      });
    } else if (Array.isArray(devices) && devices.length > 0) {
      list = devices
        .map((dev) => ({
          ip: dev.ip,
          hostname: dev.hostname || `Dev ${dev.ip}`,
          bytes: Number(dev.bandwidth_bytes || dev.bytes_transferred || 0),
          connections: Number(dev.active_connections || 1),
        }))
        .filter((d) => d.bytes > 0);
    }

    return list.sort((a, b) => b.bytes - a.bytes).slice(0, 5);
  }, [topDevices, devices]);

  const maxBytes = talkers.length > 0 ? Math.max(...talkers.map((t) => t.bytes), 1) : 1;

  return (
    <div className="glass-card p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-[#9AA3B8]">
            Bandwidth Consumption
          </span>
          <h3 className="text-base font-bold text-[#F1F3F9] tracking-tight">
            Top Talkers
          </h3>
        </div>
        <span className="text-[10px] font-semibold uppercase tracking-wider text-[#5E6579]">
          Top 5 By Volume
        </span>
      </div>

      {talkers.length === 0 ? (
        <div className="py-8 flex flex-col items-center justify-center text-center">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-[#9AA3B8] mb-2">
            <i className="ri-pulse-line text-lg"></i>
          </div>
          <p className="text-xs font-bold text-[#F1F3F9]">No Traffic Recorded</p>
          <p className="text-[11px] text-[#5E6579] mt-0.5">
            Top network consumers will be listed once packets traverse the interface.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {talkers.map((talker, index) => {
            const barWidth = Math.max(Math.round((talker.bytes / maxBytes) * 100), 4);

            return (
              <div
                key={talker.ip || index}
                onClick={() => onSelectDevice?.(talker.ip)}
                className="group cursor-pointer p-2.5 rounded-xl hover:bg-white/[0.03] transition-colors duration-150"
              >
                <div className="flex items-center justify-between gap-2 mb-1.5 text-xs">
                  <div className="flex items-center gap-2 truncate">
                    <span className="w-5 h-5 rounded-md bg-white/[0.04] text-[10.5px] font-bold mono text-[#9AA3B8] flex items-center justify-center shrink-0">
                      {index + 1}
                    </span>
                    <span className="font-semibold text-[#F1F3F9] truncate group-hover:text-[#60A5FA] transition-colors">
                      {talker.hostname}
                    </span>
                    <span className="mono text-[11px] text-[#5E6579] hidden sm:inline">
                      ({talker.ip})
                    </span>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[11px] text-[#5E6579]">
                      {talker.connections} {talker.connections === 1 ? 'conn' : 'conns'}
                    </span>
                    <span className="mono font-bold text-[#54C8E8]">
                      {formatByteCount(talker.bytes)}
                    </span>
                  </div>
                </div>

                {/* Proportional Usage Bar */}
                <div className="h-1.5 w-full bg-white/[0.04] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-[#60A5FA] to-[#54C8E8] transition-all duration-300"
                    style={{ width: `${barWidth}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default TopTalkersCard;

import React, { useMemo } from 'react';

const OS_CONFIG = {
  Windows: { icon: 'ri-windows-fill', color: '#60A5FA' }, // blue
  Android: { icon: 'ri-android-fill', color: '#34D399' }, // green
  Linux: { icon: 'ri-ubuntu-fill', color: '#F59E0B' }, // amber
  iOS: { icon: 'ri-apple-fill', color: '#A78BFA' }, // violet
  Others: { icon: 'ri-computer-line', color: '#54C8E8' }, // teal
};

export const DeviceTypesCard = ({ devices = [] }) => {
  const { counts, total } = useMemo(() => {
    const list = Array.isArray(devices) ? devices : [];
    const tally = {
      Windows: 0,
      Android: 0,
      Linux: 0,
      iOS: 0,
      Others: 0,
    };

    list.forEach((dev) => {
      const os = `${dev.os_family || ''} ${dev.device_type || ''} ${dev.vendor || ''}`.toLowerCase();
      if (os.includes('win')) {
        tally.Windows++;
      } else if (os.includes('android')) {
        tally.Android++;
      } else if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian')) {
        tally.Linux++;
      } else if (os.includes('ios') || os.includes('apple') || os.includes('iphone') || os.includes('ipad') || os.includes('mac')) {
        tally.iOS++;
      } else {
        tally.Others++;
      }
    });

    return { counts: tally, total: list.length };
  }, [devices]);

  return (
    <div className="glass-card p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-[#9AA3B8]">
            Fleet Composition
          </span>
          <h3 className="text-base font-bold text-[#F1F3F9] tracking-tight">
            Device Types
          </h3>
        </div>
        <span className="text-xs font-bold mono text-[#54C8E8] bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded-full">
          {total} devices
        </span>
      </div>

      {total === 0 ? (
        <div className="py-8 flex flex-col items-center justify-center text-center">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-[#9AA3B8] mb-2">
            <i className="ri-macbook-line text-lg"></i>
          </div>
          <p className="text-xs font-bold text-[#F1F3F9]">No Devices Discovered</p>
          <p className="text-[11px] text-[#5E6579] mt-0.5">
            Asset inventory will show OS composition upon gateway discovery.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {Object.entries(counts).map(([type, count]) => {
            const config = OS_CONFIG[type] || OS_CONFIG.Others;
            const percentage = total > 0 ? Math.round((count / total) * 100) : 0;

            return (
              <div key={type} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <i className={`${config.icon}`} style={{ color: config.color }}></i>
                    <span className="font-semibold text-[#F1F3F9]">{type}</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="mono font-bold text-[#F1F3F9]">{count}</span>
                    <span className="text-[#5E6579] text-[11px] w-8 text-right">{percentage}%</span>
                  </div>
                </div>

                {/* Composition Progress Bar */}
                <div className="h-1.5 w-full bg-white/[0.04] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${percentage}%`,
                      backgroundColor: config.color,
                      opacity: count > 0 ? 1 : 0,
                    }}
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

export default DeviceTypesCard;

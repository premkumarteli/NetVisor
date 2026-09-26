import React, { useMemo } from 'react';

const OS_CONFIG = {
  Windows: { icon: 'ri-windows-fill' },
  Android: { icon: 'ri-android-fill' },
  Linux: { icon: 'ri-ubuntu-fill' },
  iOS: { icon: 'ri-apple-fill' },
  Others: { icon: 'ri-computer-line' },
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
    <div
      className="glass-card p-5 flex flex-col justify-between"
      style={{
        background: 'rgba(10, 14, 26, 0.72)',
        backdropFilter: 'blur(20px) saturate(150%)',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
      }}
    >
      {/* Header matching reference */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <i className="ri-computer-line text-[#9AA3B8] text-base"></i>
          <h3 className="text-sm font-bold text-[#FFFFFF] tracking-tight">
            Device Types
          </h3>
        </div>
        <span className="text-xs text-[#9AA3B8]">
          Total <strong className="text-[#FFFFFF] mono font-bold">{total}</strong>
        </span>
      </div>

      <div className="space-y-2.5">
        {Object.entries(counts).map(([type, count]) => {
          const config = OS_CONFIG[type] || OS_CONFIG.Others;
          const percentage = total > 0 ? Math.round((count / total) * 100) : 0;

          return (
            <div key={type} className="flex items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2 w-20 shrink-0 text-[#9AA3B8]">
                <i className={`${config.icon} text-sm text-[#5E6579]`}></i>
                <span className="truncate">{type}</span>
              </div>

              <span className="mono font-semibold text-[#FFFFFF] w-6 text-right shrink-0">
                {count}
              </span>

              {/* Composition Progress Bar (Blue-gradient rounded bar per reference) */}
              <div className="flex-1 h-2 bg-white/[0.04] rounded-full overflow-hidden mx-2">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-blue-600 to-blue-400 transition-all duration-500"
                  style={{
                    width: `${percentage}%`,
                    opacity: count > 0 ? 1 : 0,
                  }}
                />
              </div>

              <span className="mono text-[#9AA3B8] text-[11px] w-8 text-right shrink-0">
                {percentage}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default DeviceTypesCard;

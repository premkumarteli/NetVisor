import React, { useMemo } from 'react';

export const TopologyGraph = ({
  devices = [],
  activity = [],
  onSelectDevice,
  trustStatusProps = {},
}) => {
  const topDevices = useMemo(() => {
    if (!Array.isArray(devices) || devices.length === 0) return [];
    return [...devices]
      .sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0))
      .slice(0, 12);
  }, [devices]);

  // Constellation coordinate calculations
  const constellation = useMemo(() => {
    const cx = 320;
    const cy = 110;
    const rx = 230;
    const ry = 80;

    const angleStep = (2 * Math.PI) / (topDevices.length || 1);

    return topDevices.map((device, index) => {
      // Oval orbit distribution
      const rMultiplier = 0.82 + ((index % 3) * 0.12);
      const angle = index * angleStep - Math.PI / 2;
      const x = Math.round(cx + rx * rMultiplier * Math.cos(angle));
      const y = Math.round(cy + ry * rMultiplier * Math.sin(angle));

      const isHighRisk = (Number(device.risk_score) || 0) >= 60 || ['CRITICAL', 'HIGH'].includes(String(device.risk_level).toUpperCase());
      const isVpn = Boolean(device.is_vpn || device.vpn_provider || device.detection_type === 'vpn');
      const isNew = Boolean(device.is_new);

      let toneColor = '#60A5FA'; // Normal (cyan/blue)
      if (isHighRisk) {
        toneColor = '#EF4444'; // High Risk (crimson)
      } else if (isVpn) {
        toneColor = '#8B5CF6'; // VPN (purple)
      } else if (isNew) {
        toneColor = '#10B981'; // New Device (teal)
      }

      // Device icon inference
      const os = `${device.os_family || ''} ${device.device_type || ''} ${device.hostname || ''}`.toLowerCase();
      let icon = 'ri-macbook-line';
      if (os.includes('phone') || os.includes('android') || os.includes('ios') || os.includes('iphone')) {
        icon = 'ri-smartphone-line';
      } else if (os.includes('server') || os.includes('linux')) {
        icon = 'ri-server-line';
      } else if (os.includes('tv')) {
        icon = 'ri-tv-line';
      } else if (os.includes('print')) {
        icon = 'ri-printer-line';
      } else if (os.includes('cam')) {
        icon = 'ri-camera-line';
      } else if (os.includes('pc') || os.includes('desktop') || os.includes('win')) {
        icon = 'ri-computer-line';
      }

      return {
        device,
        x,
        y,
        toneColor,
        icon,
        isHighRisk,
        isVpn,
      };
    });
  }, [topDevices]);

  return (
    <div
      className="glass-card flex flex-col h-[260px] relative overflow-hidden"
      style={{
        background: 'rgba(10, 14, 26, 0.78)',
        backdropFilter: 'blur(24px) saturate(160%)',
        WebkitBackdropFilter: 'blur(24px) saturate(160%)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: '0 8px 30px rgba(0, 0, 0, 0.4)',
      }}
    >
      {/* Topology Header matching reference */}
      <div className="px-3.5 py-2 border-b border-white/[0.06] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-[#60A5FA]">
            <i className="ri-global-line text-xs"></i>
          </div>
          <div>
            <h3 className="text-xs font-bold text-[#FFFFFF] tracking-tight">
              Network Activity
            </h3>
            <p className="text-[9.5px] text-[#9AA3B8]">
              Live device connections and traffic flow
            </p>
          </div>
        </div>

        {/* Legend matching reference */}
        <div className="flex items-center gap-3 text-[10px] text-[#9AA3B8]">
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[#60A5FA]" /> Normal
          </span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[#8B5CF6]" /> VPN
          </span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444]" /> High Risk
          </span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" /> New Device
          </span>
          <button type="button" className="text-[#5E6579] hover:text-white ml-1" title="Expand view">
            <i className="ri-fullscreen-line text-xs"></i>
          </button>
        </div>
      </div>

      {/* Constellation Canvas Viewport */}
      <div className="relative flex-1 w-full h-full overflow-hidden flex items-center justify-center select-none">
        {/* SVG Edge Vectors & Radar Circles */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 640 220" preserveAspectRatio="xMidYMid meet">
          <defs>
            <radialGradient id="gwGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.35" />
              <stop offset="60%" stopColor="#3B82F6" stopOpacity="0.08" />
              <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Ambient Radar Circles */}
          <ellipse cx="320" cy="110" rx="230" ry="80" fill="none" stroke="rgba(255, 255, 255, 0.03)" strokeWidth="1" strokeDasharray="3 3" />
          <ellipse cx="320" cy="110" rx="140" ry="50" fill="none" stroke="rgba(255, 255, 255, 0.04)" strokeWidth="1" />
          <circle cx="320" cy="110" r="45" fill="url(#gwGlow)" />

          {/* Connected Lines from Hub to Endpoints */}
          {constellation.map((node, i) => (
            <g key={`line-${i}`}>
              <line
                x1="320"
                y1="110"
                x2={node.x}
                y2={node.y}
                stroke={node.toneColor}
                strokeOpacity={node.isHighRisk ? 0.6 : 0.25}
                strokeWidth={node.isHighRisk ? 1.5 : 1}
                strokeDasharray={node.isVpn ? '4 2' : 'none'}
              />
              {/* Micro packet pulse dot along edge */}
              <circle
                cx={320 + (node.x - 320) * 0.55}
                cy={110 + (node.y - 110) * 0.55}
                r="1.5"
                fill={node.toneColor}
                opacity="0.8"
              />
            </g>
          ))}
        </svg>

        {/* Center Gateway Hub Router */}
        <div
          className="absolute z-10 flex items-center justify-center -translate-x-1/2 -translate-y-1/2"
          style={{ left: '50%', top: '50%' }}
        >
          {/* Animated ping ring */}
          <div className="absolute w-16 h-16 rounded-full bg-blue-500/15 animate-ping pointer-events-none" style={{ animationDuration: '3s' }} />
          <div className="relative w-11 h-11 rounded-full bg-[#0F172A] border-2 border-[#3B82F6] shadow-[0_0_20px_rgba(59,130,246,0.5)] flex items-center justify-center text-[#60A5FA]">
            <i className="ri-router-line text-lg"></i>
          </div>
        </div>

        {/* Device Endpoint Nodes */}
        {constellation.map((node, i) => {
          // Normalize position percentage
          const leftPercent = (node.x / 640) * 100;
          const topPercent = (node.y / 220) * 100;

          return (
            <div
              key={node.device.ip || i}
              onClick={() => onSelectDevice?.(node.device.ip)}
              className="absolute z-20 group cursor-pointer -translate-x-1/2 -translate-y-1/2 flex flex-col items-center justify-center transition-transform duration-150 hover:scale-115"
              style={{ left: `${leftPercent}%`, top: `${topPercent}%` }}
            >
              {/* Circular Node */}
              <div
                className="w-7.5 h-7.5 rounded-full bg-[#0B0F1A]/95 flex items-center justify-center text-xs shadow-md transition-all duration-150"
                style={{
                  border: `1.5px solid ${node.toneColor}`,
                  color: node.toneColor,
                  boxShadow: `0 0 10px ${node.toneColor}40`,
                }}
              >
                <i className={node.icon}></i>
              </div>

              {/* Hover Badge */}
              <span className="hidden group-hover:block absolute top-8.5 text-[8.5px] font-medium text-white px-1.5 py-0.2 rounded bg-black/80 border border-white/10 whitespace-nowrap z-30 mono">
                {node.device.hostname || node.device.ip}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default TopologyGraph;


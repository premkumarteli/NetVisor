import React, { useMemo, useState } from 'react';

const MOCK_NODES = [
  { id: '1', ip: '192.168.1.10', hostname: 'Laptop-01', type: 'laptop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 140, y: 70 },
  { id: '2', ip: '192.168.1.15', hostname: 'Android-12', type: 'phone', os: 'Android', risk: 'VPN', color: '#8B5CF6', icon: 'ri-smartphone-line', x: 235, y: 48 },
  { id: '3', ip: '192.168.1.20', hostname: 'PC-Office', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-computer-line', x: 345, y: 45 },
  { id: '4', ip: '192.168.1.25', hostname: 'iPhone', type: 'phone', os: 'iOS', risk: 'High Risk', color: '#EF4444', icon: 'ri-smartphone-line', x: 455, y: 55 },
  { id: '5', ip: '192.168.1.30', hostname: 'Server-01', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-server-line', x: 545, y: 80 },
  { id: '6', ip: '192.168.1.35', hostname: 'SmartTV', type: 'tv', os: 'Others', risk: 'Normal', color: '#60A5FA', icon: 'ri-tv-line', x: 560, y: 155 },
  { id: '7', ip: '192.168.1.40', hostname: 'Printer-HQ', type: 'printer', os: 'Others', risk: 'New Device', color: '#10B981', icon: 'ri-printer-line', x: 480, y: 175 },
  { id: '8', ip: '192.168.1.45', hostname: 'Security-Cam', type: 'camera', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-camera-line', x: 375, y: 185 },
  { id: '9', ip: '192.168.1.50', hostname: 'VPN-Gateway', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 275, y: 180 },
  { id: '10', ip: '192.168.1.55', hostname: 'New-Device', type: 'phone', os: 'Android', risk: 'High Risk', color: '#EF4444', icon: 'ri-smartphone-line', x: 220, y: 145 },
  { id: '11', ip: '192.168.1.60', hostname: 'Backup-NAS', type: 'storage', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-hard-drive-2-line', x: 95, y: 125 },
  { id: '12', ip: '192.168.1.65', hostname: 'Tablet-02', type: 'tablet', os: 'iOS', risk: 'Normal', color: '#60A5FA', icon: 'ri-tablet-line', x: 75, y: 165 },
  { id: '13', ip: '192.168.1.70', hostname: 'Workstation', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 405, y: 120 },
];

export const TopologyGraph = ({
  devices = [],
  activity = [],
  onSelectDevice,
}) => {
  const [hoveredNode, setHoveredNode] = useState(null);

  // Map real devices to constellation positions or fallback to 13-node reference constellation
  const nodes = useMemo(() => {
    return MOCK_NODES.map((mockNode, index) => {
      const realDevice = Array.isArray(devices) && devices[index] ? devices[index] : null;
      if (!realDevice) return mockNode;

      const isHighRisk =
        (Number(realDevice.risk_score) || 0) >= 60 ||
        ['CRITICAL', 'HIGH'].includes(String(realDevice.risk_level).toUpperCase());
      const isVpn = Boolean(realDevice.is_vpn || realDevice.vpn_provider || realDevice.detection_type === 'vpn');
      const isNew = Boolean(realDevice.is_new);

      let color = '#60A5FA';
      let riskLabel = 'Normal';
      if (isHighRisk) {
        color = '#EF4444';
        riskLabel = 'High Risk';
      } else if (isVpn) {
        color = '#8B5CF6';
        riskLabel = 'VPN';
      } else if (isNew) {
        color = '#10B981';
        riskLabel = 'New Device';
      }

      return {
        ...mockNode,
        ip: realDevice.ip || mockNode.ip,
        hostname: realDevice.hostname || mockNode.hostname,
        risk: riskLabel,
        color,
      };
    });
  }, [devices]);

  return (
    <div
      className="glass-card flex flex-col h-[270px] relative overflow-hidden rounded-2xl"
      style={{
        background: 'rgba(10, 14, 26, 0.76)',
        backdropFilter: 'blur(24px) saturate(160%)',
        WebkitBackdropFilter: 'blur(24px) saturate(160%)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.45)',
      }}
    >
      {/* Topology Header */}
      <div className="px-4 py-2.5 border-b border-white/[0.06] flex items-center justify-between gap-3 shrink-0">
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

        {/* Legend */}
        <div className="flex items-center gap-3 text-[10px] text-[#9AA3B8]">
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#60A5FA]" /> Normal
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#8B5CF6]" /> VPN
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444]" /> High Risk
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" /> New Device
          </span>
          <button
            type="button"
            className="text-[#5E6579] hover:text-white ml-1 p-0.5"
            title="Expand view"
          >
            <i className="ri-fullscreen-line text-xs"></i>
          </button>
        </div>
      </div>

      {/* SVG Observatory Constellation Canvas */}
      <div className="relative flex-1 w-full h-full overflow-hidden select-none">
        <svg
          className="w-full h-full"
          viewBox="0 0 640 220"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            {/* Center Router Hub Glow */}
            <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.4" />
              <stop offset="50%" stopColor="#3B82F6" stopOpacity="0.12" />
              <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
            </radialGradient>

            {/* Glowing filter for nodes */}
            <filter id="nodeGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background Orbit Radar Grid Rings */}
          <ellipse
            cx="320"
            cy="110"
            rx="250"
            ry="90"
            fill="none"
            stroke="rgba(255, 255, 255, 0.03)"
            strokeWidth="1"
            strokeDasharray="4 4"
          />
          <ellipse
            cx="320"
            cy="110"
            rx="160"
            ry="60"
            fill="none"
            stroke="rgba(255, 255, 255, 0.04)"
            strokeWidth="1"
          />
          <circle cx="320" cy="110" r="55" fill="url(#hubGlow)" />

          {/* Constellation Spoke Lines from Hub (320, 110) to each Node */}
          {nodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            return (
              <g key={`spoke-${node.id}`}>
                <line
                  x1="320"
                  y1="110"
                  x2={node.x}
                  y2={node.y}
                  stroke={node.color}
                  strokeOpacity={isHovered ? 0.8 : node.risk === 'High Risk' ? 0.5 : 0.22}
                  strokeWidth={isHovered ? 1.5 : node.risk === 'High Risk' ? 1.2 : 0.8}
                  strokeDasharray={node.risk === 'VPN' ? '4 3' : 'none'}
                />
                {/* Data Packet Pulse on spoke */}
                <circle
                  cx={320 + (node.x - 320) * 0.52}
                  cy={110 + (node.y - 110) * 0.52}
                  r={isHovered ? 2.5 : 1.5}
                  fill={node.color}
                  opacity={isHovered ? 1 : 0.85}
                />
              </g>
            );
          })}

          {/* Satellite Orbiting Device Nodes */}
          {nodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            const r = 13;

            return (
              <g
                key={`node-${node.id}`}
                className="cursor-pointer transition-all duration-150"
                onClick={() => onSelectDevice?.(node.ip)}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Glow ring on hover */}
                {isHovered && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={r + 4}
                    fill="none"
                    stroke={node.color}
                    strokeWidth="1.5"
                    strokeOpacity="0.6"
                    className="animate-pulse"
                  />
                )}

                {/* Node Solid Circle */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r}
                  fill="#0B0F1A"
                  stroke={node.color}
                  strokeWidth={isHovered ? 2 : 1.5}
                />

                {/* Device Icon inside Node */}
                <foreignObject
                  x={node.x - 10}
                  y={node.y - 10}
                  width="20"
                  height="20"
                  className="pointer-events-none"
                >
                  <div
                    className="w-full h-full flex items-center justify-center text-[10px]"
                    style={{ color: node.color }}
                  >
                    <i className={node.icon}></i>
                  </div>
                </foreignObject>
              </g>
            );
          })}

          {/* Center Router Hub Gateway (320, 110) */}
          <g className="pointer-events-none">
            {/* Outer halo */}
            <circle
              cx="320"
              cy="110"
              r="24"
              fill="#0F172A"
              stroke="#3B82F6"
              strokeWidth="2"
              filter="url(#nodeGlow)"
            />
            {/* Inner router badge */}
            <foreignObject x="306" y="96" width="28" height="28">
              <div className="w-full h-full flex items-center justify-center text-sm text-[#60A5FA]">
                <i className="ri-router-line"></i>
              </div>
            </foreignObject>
          </g>
        </svg>

        {/* Hover Tooltip Overlay */}
        {hoveredNode && (
          <div
            className="absolute z-30 pointer-events-none px-2 py-1 rounded-md bg-[#0F172A]/95 border border-white/15 shadow-xl text-[10px] text-white flex flex-col gap-0.5 -translate-x-1/2 -translate-y-full"
            style={{
              left: `${(hoveredNode.x / 640) * 100}%`,
              top: `${(hoveredNode.y / 220) * 100 - 8}%`,
            }}
          >
            <span className="font-bold text-[#F1F3F9] leading-none">{hoveredNode.hostname}</span>
            <span className="mono text-[8.5px] text-[#9AA3B8]">{hoveredNode.ip} • {hoveredNode.risk}</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default TopologyGraph;

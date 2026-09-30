import React, { useMemo, useState } from 'react';

const MOCK_NODES = [
  { id: '1', ip: '192.168.1.10', hostname: 'Laptop-01', type: 'laptop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 155, y: 75 },
  { id: '2', ip: '192.168.1.15', hostname: 'Android-12', type: 'phone', os: 'Android', risk: 'VPN', color: '#8B5CF6', icon: 'ri-smartphone-line', x: 265, y: 52 },
  { id: '3', ip: '192.168.1.20', hostname: 'PC-Office', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-computer-line', x: 390, y: 48 },
  { id: '4', ip: '192.168.1.25', hostname: 'iPhone', type: 'phone', os: 'iOS', risk: 'High Risk', color: '#EF4444', icon: 'ri-smartphone-line', x: 515, y: 60 },
  { id: '5', ip: '192.168.1.30', hostname: 'Server-01', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-server-line', x: 615, y: 90 },
  { id: '6', ip: '192.168.1.35', hostname: 'SmartTV', type: 'tv', os: 'Others', risk: 'Normal', color: '#60A5FA', icon: 'ri-tv-line', x: 635, y: 175 },
  { id: '7', ip: '192.168.1.40', hostname: 'Printer-HQ', type: 'printer', os: 'Others', risk: 'New Device', color: '#10B981', icon: 'ri-printer-line', x: 540, y: 200 },
  { id: '8', ip: '192.168.1.45', hostname: 'Security-Cam', type: 'camera', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-camera-line', x: 425, y: 210 },
  { id: '9', ip: '192.168.1.50', hostname: 'VPN-Gateway', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 310, y: 205 },
  { id: '10', ip: '192.168.1.55', hostname: 'New-Device', type: 'phone', os: 'Android', risk: 'High Risk', color: '#EF4444', icon: 'ri-smartphone-line', x: 245, y: 165 },
  { id: '11', ip: '192.168.1.60', hostname: 'Backup-NAS', type: 'storage', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-hard-drive-2-line', x: 105, y: 140 },
  { id: '12', ip: '192.168.1.65', hostname: 'Tablet-02', type: 'tablet', os: 'iOS', risk: 'Normal', color: '#60A5FA', icon: 'ri-tablet-line', x: 85, y: 188 },
  { id: '13', ip: '192.168.1.70', hostname: 'Workstation', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 460, y: 135 },
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
      className="glass-card flex flex-col h-[310px] relative overflow-hidden"
    >
      {/* Topology Header */}
      <div className="px-4 py-3 border-b border-white/[0.08] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-[#60A5FA] shadow-sm">
            <i className="ri-global-line text-sm"></i>
          </div>
          <div>
            <h3 className="text-sm font-bold text-[#FFFFFF] tracking-tight">
              Network Activity
            </h3>
            <p className="text-[10.5px] text-[#9AA3B8]">
              Live device connections and traffic flow
            </p>
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3.5 text-[11px] text-[#9AA3B8]">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#60A5FA] shadow-[0_0_6px_#60A5FA]" /> Normal
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#8B5CF6] shadow-[0_0_6px_#8B5CF6]" /> VPN
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#EF4444] shadow-[0_0_6px_#EF4444]" /> High Risk
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#10B981] shadow-[0_0_6px_#10B981]" /> New Device
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

      {/* SVG Observatory Constellation Canvas (Scaled 720x250) */}
      <div className="relative flex-1 w-full h-full overflow-hidden select-none">
        <svg
          className="w-full h-full"
          viewBox="0 0 720 250"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            {/* Center Router Hub Glow */}
            <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.45" />
              <stop offset="50%" stopColor="#3B82F6" stopOpacity="0.15" />
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
            cx="360"
            cy="125"
            rx="285"
            ry="105"
            fill="none"
            stroke="rgba(255, 255, 255, 0.04)"
            strokeWidth="1"
            strokeDasharray="4 4"
          />
          <ellipse
            cx="360"
            cy="125"
            rx="180"
            ry="70"
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth="1"
          />
          <circle cx="360" cy="125" r="65" fill="url(#hubGlow)" />

          {/* Constellation Spoke Lines from Hub (360, 125) to each Node */}
          {nodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            return (
              <g key={`spoke-${node.id}`}>
                <line
                  x1="360"
                  y1="125"
                  x2={node.x}
                  y2={node.y}
                  stroke={node.color}
                  strokeOpacity={isHovered ? 0.85 : node.risk === 'High Risk' ? 0.55 : 0.25}
                  strokeWidth={isHovered ? 1.8 : node.risk === 'High Risk' ? 1.4 : 1}
                  strokeDasharray={node.risk === 'VPN' ? '4 3' : 'none'}
                />
                {/* Data Packet Pulse on spoke */}
                <circle
                  cx={360 + (node.x - 360) * 0.52}
                  cy={125 + (node.y - 125) * 0.52}
                  r={isHovered ? 3 : 1.8}
                  fill={node.color}
                  opacity={isHovered ? 1 : 0.85}
                  filter="url(#nodeGlow)"
                />
              </g>
            );
          })}

          {/* Satellite Orbiting Device Nodes */}
          {nodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            const r = 15;

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
                    r={r + 5}
                    fill="none"
                    stroke={node.color}
                    strokeWidth="1.8"
                    strokeOpacity="0.7"
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
                  strokeWidth={isHovered ? 2.2 : 1.6}
                  style={{ filter: `drop-shadow(0 0 6px ${node.color}40)` }}
                />

                {/* Device Icon inside Node */}
                <foreignObject
                  x={node.x - 11}
                  y={node.y - 11}
                  width="22"
                  height="22"
                  className="pointer-events-none"
                >
                  <div
                    className="w-full h-full flex items-center justify-center text-[11px]"
                    style={{ color: node.color }}
                  >
                    <i className={node.icon}></i>
                  </div>
                </foreignObject>
              </g>
            );
          })}

          {/* Center Router Hub Gateway (360, 125) */}
          <g className="pointer-events-none">
            {/* Outer halo */}
            <circle
              cx="360"
              cy="125"
              r="28"
              fill="#0F172A"
              stroke="#3B82F6"
              strokeWidth="2.2"
              filter="url(#nodeGlow)"
              style={{ filter: 'drop-shadow(0 0 16px rgba(59,130,246,0.6))' }}
            />
            {/* Inner router badge */}
            <foreignObject x="345" y="110" width="30" height="30">
              <div className="w-full h-full flex items-center justify-center text-base text-[#60A5FA]">
                <i className="ri-router-line"></i>
              </div>
            </foreignObject>
          </g>
        </svg>

        {/* Hover Tooltip Overlay */}
        {hoveredNode && (
          <div
            className="absolute z-30 pointer-events-none px-2.5 py-1.5 rounded-lg bg-[#0F172A]/95 border border-white/20 shadow-2xl text-[10.5px] text-white flex flex-col gap-0.5 -translate-x-1/2 -translate-y-full"
            style={{
              left: `${(hoveredNode.x / 720) * 100}%`,
              top: `${(hoveredNode.y / 250) * 100 - 8}%`,
            }}
          >
            <span className="font-bold text-[#F1F3F9] leading-none">{hoveredNode.hostname}</span>
            <span className="mono text-[9px] text-[#9AA3B8]">{hoveredNode.ip} • {hoveredNode.risk}</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default TopologyGraph;

import React, { useMemo, useState } from 'react';

const MOCK_NODES = [
  { id: '1', ip: '192.168.1.10', hostname: 'Laptop-01', type: 'laptop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 155, y: 75, pulseSpeed: '2.4s' },
  { id: '2', ip: '192.168.1.15', hostname: 'Android-12', type: 'phone', os: 'Android', risk: 'VPN', color: '#8B5CF6', icon: 'ri-smartphone-line', x: 265, y: 52, pulseSpeed: '1.8s' },
  { id: '3', ip: '192.168.1.20', hostname: 'PC-Office', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-computer-line', x: 390, y: 48, pulseSpeed: '3.1s' },
  { id: '4', ip: '192.168.1.25', hostname: 'iPhone', type: 'phone', os: 'iOS', risk: 'High Risk', color: '#EF4444', icon: 'ri-smartphone-line', x: 515, y: 60, pulseSpeed: '1.5s' },
  { id: '5', ip: '192.168.1.30', hostname: 'Server-01', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-server-line', x: 615, y: 90, pulseSpeed: '2.8s' },
  { id: '6', ip: '192.168.1.35', hostname: 'SmartTV', type: 'tv', os: 'Others', risk: 'Normal', color: '#60A5FA', icon: 'ri-tv-line', x: 635, y: 175, pulseSpeed: '3.5s' },
  { id: '7', ip: '192.168.1.40', hostname: 'Printer-HQ', type: 'printer', os: 'Others', risk: 'New Device', color: '#10B981', icon: 'ri-printer-line', x: 540, y: 200, pulseSpeed: '2.2s' },
  { id: '8', ip: '192.168.1.45', hostname: 'Security-Cam', type: 'camera', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-camera-line', x: 425, y: 210, pulseSpeed: '2.6s' },
  { id: '9', ip: '192.168.1.50', hostname: 'VPN-Gateway', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 310, y: 205, pulseSpeed: '2.0s' },
  { id: '10', ip: '192.168.1.55', hostname: 'New-Device', type: 'phone', os: 'Android', risk: 'High Risk', color: '#EF4444', icon: 'ri-smartphone-line', x: 245, y: 165, pulseSpeed: '1.6s' },
  { id: '11', ip: '192.168.1.60', hostname: 'Backup-NAS', type: 'storage', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-hard-drive-2-line', x: 105, y: 140, pulseSpeed: '3.0s' },
  { id: '12', ip: '192.168.1.65', hostname: 'Tablet-02', type: 'tablet', os: 'iOS', risk: 'Normal', color: '#60A5FA', icon: 'ri-tablet-line', x: 85, y: 188, pulseSpeed: '2.7s' },
  { id: '13', ip: '192.168.1.70', hostname: 'Workstation', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 460, y: 135, pulseSpeed: '2.3s' },
];

export const TopologyGraph = ({
  devices = [],
  activity = [],
  onSelectDevice,
}) => {
  const [hoveredNode, setHoveredNode] = useState(null);
  const [activeFilter, setActiveFilter] = useState('ALL');

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
    <div className="glass-card flex flex-col h-[310px] relative overflow-hidden group/card">
      {/* Dynamic ambient background glow */}
      <div className="absolute -top-24 -left-24 w-72 h-72 bg-blue-500/10 rounded-full blur-3xl pointer-events-none transition-opacity duration-500 group-hover/card:bg-blue-500/15" />
      <div className="absolute -bottom-24 -right-24 w-72 h-72 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none transition-opacity duration-500 group-hover/card:bg-indigo-500/15" />

      {/* Topology Header */}
      <div className="px-4 py-3 border-b border-white/[0.08] flex items-center justify-between gap-3 shrink-0 relative z-10">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-[#60A5FA] shadow-[0_0_12px_rgba(96,165,250,0.25)]">
            <i className="ri-global-line text-sm animate-spin" style={{ animationDuration: '20s' }}></i>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-[#FFFFFF] tracking-tight">
                Network Activity
              </h3>
              <span className="flex items-center gap-1 px-1.5 py-0.2 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-[9px] font-bold text-[#34D399]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#34D399] animate-pulse" />
                LIVE
              </span>
            </div>
            <p className="text-[10.5px] text-[#9AA3B8]">
              Live device connections and traffic flow
            </p>
          </div>
        </div>

        {/* Legend with interactive category filters */}
        <div className="flex items-center gap-2.5 text-[11px] text-[#9AA3B8]">
          {[
            { id: 'Normal', label: 'Normal', color: '#60A5FA' },
            { id: 'VPN', label: 'VPN', color: '#8B5CF6' },
            { id: 'High Risk', label: 'High Risk', color: '#EF4444' },
            { id: 'New Device', label: 'New Device', color: '#10B981' },
          ].map((cat) => {
            const isSelected = activeFilter === cat.id;
            return (
              <button
                key={cat.id}
                type="button"
                onClick={() => setActiveFilter(activeFilter === cat.id ? 'ALL' : cat.id)}
                className={`flex items-center gap-1.5 px-2 py-0.5 rounded-md transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-white/10 text-white shadow-sm ring-1 ring-white/20'
                    : 'hover:text-white hover:bg-white/[0.04]'
                }`}
              >
                <span
                  className="w-2 h-2 rounded-full transition-transform"
                  style={{
                    backgroundColor: cat.color,
                    boxShadow: `0 0 8px ${cat.color}`,
                    transform: isSelected ? 'scale(1.2)' : 'scale(1)',
                  }}
                />
                <span className="text-[10.5px]">{cat.label}</span>
              </button>
            );
          })}
          <button
            type="button"
            onClick={() => setActiveFilter('ALL')}
            className="text-[#5E6579] hover:text-white ml-1 p-0.5 transition-colors cursor-pointer"
            title="Reset filter"
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
              <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.55" />
              <stop offset="40%" stopColor="#3B82F6" stopOpacity="0.2" />
              <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
            </radialGradient>

            {/* Glowing filter for nodes */}
            <filter id="nodeGlow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>

            {/* Intense glow for hovered spoke lines */}
            <filter id="lineGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2" result="blur" />
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
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth="1"
            strokeDasharray="5 5"
          />
          <ellipse
            cx="360"
            cy="125"
            rx="180"
            ry="70"
            fill="none"
            stroke="rgba(255, 255, 255, 0.06)"
            strokeWidth="1"
          />
          <circle cx="360" cy="125" r="75" fill="url(#hubGlow)" />

          {/* Constellation Spoke Lines from Hub (360, 125) to each Node */}
          {nodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            const isDimmed =
              (hoveredNode && hoveredNode.id !== node.id) ||
              (activeFilter !== 'ALL' && activeFilter !== node.risk);

            return (
              <g key={`spoke-${node.id}`} opacity={isDimmed ? 0.2 : 1} className="transition-opacity duration-200">
                {/* Background Spoke Line */}
                <line
                  x1="360"
                  y1="125"
                  x2={node.x}
                  y2={node.y}
                  stroke={node.color}
                  strokeOpacity={isHovered ? 0.95 : node.risk === 'High Risk' ? 0.6 : 0.3}
                  strokeWidth={isHovered ? 2.5 : node.risk === 'High Risk' ? 1.6 : 1.1}
                  strokeDasharray={node.risk === 'VPN' ? '4 3' : 'none'}
                  filter={isHovered ? 'url(#lineGlow)' : undefined}
                />

                {/* Animated Flowing Data Packets on Spoke */}
                <circle
                  cx={360 + (node.x - 360) * 0.35}
                  cy={125 + (node.y - 125) * 0.35}
                  r={isHovered ? 3.5 : 2}
                  fill={node.color}
                  opacity={isHovered ? 1 : 0.85}
                  filter="url(#nodeGlow)"
                >
                  <animate
                    attributeName="cx"
                    values={`${360};${node.x}`}
                    dur={node.pulseSpeed || '2.5s'}
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="cy"
                    values={`${125};${node.y}`}
                    dur={node.pulseSpeed || '2.5s'}
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="opacity"
                    values="0;0.9;0.9;0"
                    dur={node.pulseSpeed || '2.5s'}
                    repeatCount="indefinite"
                  />
                </circle>

                {/* Secondary Offset Packet for High Traffic / High Risk */}
                {(node.risk === 'High Risk' || node.risk === 'VPN') && (
                  <circle
                    cx={360 + (node.x - 360) * 0.7}
                    cy={125 + (node.y - 125) * 0.7}
                    r={isHovered ? 3 : 1.6}
                    fill={node.color}
                    opacity="0.75"
                    filter="url(#nodeGlow)"
                  >
                    <animate
                      attributeName="cx"
                      values={`${node.x};${360}`}
                      dur="3s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="cy"
                      values={`${node.y};${125}`}
                      dur="3s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="opacity"
                      values="0;0.8;0.8;0"
                      dur="3s"
                      repeatCount="indefinite"
                    />
                  </circle>
                )}
              </g>
            );
          })}

          {/* Satellite Orbiting Device Nodes */}
          {nodes.map((node) => {
            const isHovered = hoveredNode?.id === node.id;
            const isDimmed =
              (hoveredNode && hoveredNode.id !== node.id) ||
              (activeFilter !== 'ALL' && activeFilter !== node.risk);
            const r = isHovered ? 17 : 15;

            return (
              <g
                key={`node-${node.id}`}
                className="cursor-pointer transition-all duration-200"
                opacity={isDimmed ? 0.25 : 1}
                onClick={() => onSelectDevice?.(node.ip)}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Radiant Pulsing Ring on Hover or High Risk */}
                {(isHovered || node.risk === 'High Risk') && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={r + 6}
                    fill="none"
                    stroke={node.color}
                    strokeWidth="1.8"
                    strokeOpacity={isHovered ? '0.8' : '0.4'}
                  >
                    <animate
                      attributeName="r"
                      values={`${r + 2};${r + 8};${r + 2}`}
                      dur="2s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="stroke-opacity"
                      values="0.8;0.2;0.8"
                      dur="2s"
                      repeatCount="indefinite"
                    />
                  </circle>
                )}

                {/* Node Solid Obsidian Disc */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r}
                  fill="#0B0F1A"
                  stroke={node.color}
                  strokeWidth={isHovered ? 2.5 : 1.8}
                  style={{
                    filter: `drop-shadow(0 0 ${isHovered ? '12px' : '6px'} ${node.color})`,
                  }}
                />

                {/* Device Icon inside Node */}
                <foreignObject
                  x={node.x - (isHovered ? 12 : 11)}
                  y={node.y - (isHovered ? 12 : 11)}
                  width={isHovered ? 24 : 22}
                  height={isHovered ? 24 : 22}
                  className="pointer-events-none"
                >
                  <div
                    className="w-full h-full flex items-center justify-center text-[11px] transition-transform"
                    style={{ color: node.color, transform: isHovered ? 'scale(1.15)' : 'scale(1)' }}
                  >
                    <i className={node.icon}></i>
                  </div>
                </foreignObject>
              </g>
            );
          })}

          {/* Center Router Hub Gateway (360, 125) with Concentric Animated Beacon Waves */}
          <g className="pointer-events-none">
            {/* Concentric Radar Wave 1 */}
            <circle cx="360" cy="125" r="42" fill="none" stroke="#3B82F6" strokeWidth="1" opacity="0.3">
              <animate
                attributeName="r"
                values="28;56"
                dur="3s"
                repeatCount="indefinite"
              />
              <animate
                attributeName="opacity"
                values="0.4;0"
                dur="3s"
                repeatCount="indefinite"
              />
            </circle>

            {/* Concentric Radar Wave 2 */}
            <circle cx="360" cy="125" r="32" fill="none" stroke="#60A5FA" strokeWidth="1.2" opacity="0.5">
              <animate
                attributeName="r"
                values="28;46"
                dur="2s"
                repeatCount="indefinite"
              />
              <animate
                attributeName="opacity"
                values="0.6;0"
                dur="2s"
                repeatCount="indefinite"
              />
            </circle>

            {/* Outer solid halo */}
            <circle
              cx="360"
              cy="125"
              r="28"
              fill="#0F172A"
              stroke="#3B82F6"
              strokeWidth="2.4"
              style={{ filter: 'drop-shadow(0 0 18px rgba(59,130,246,0.75))' }}
            />

            {/* Inner router badge */}
            <foreignObject x="345" y="110" width="30" height="30">
              <div className="w-full h-full flex items-center justify-center text-base text-[#60A5FA] drop-shadow-[0_0_8px_#60A5FA]">
                <i className="ri-router-line"></i>
              </div>
            </foreignObject>
          </g>
        </svg>

        {/* Hover Tooltip Overlay with Glowing Badge */}
        {hoveredNode && (
          <div
            className="absolute z-30 pointer-events-none px-3 py-1.5 rounded-xl bg-[#0B0F1A]/95 border border-white/20 shadow-[0_10px_30px_rgba(0,0,0,0.8),0_0_20px_rgba(96,165,250,0.25)] text-xs text-white flex flex-col gap-0.5 -translate-x-1/2 -translate-y-full transition-all duration-150 animate-in fade-in zoom-in-95"
            style={{
              left: `${(hoveredNode.x / 720) * 100}%`,
              top: `${(hoveredNode.y / 250) * 100 - 10}%`,
            }}
          >
            <div className="flex items-center gap-1.5">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: hoveredNode.color, boxShadow: `0 0 8px ${hoveredNode.color}` }}
              />
              <span className="font-bold text-[#F1F3F9] text-xs">{hoveredNode.hostname}</span>
            </div>
            <div className="flex items-center gap-2 mono text-[10px] text-[#9AA3B8]">
              <span>{hoveredNode.ip}</span>
              <span>•</span>
              <span style={{ color: hoveredNode.color }}>{hoveredNode.risk}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TopologyGraph;

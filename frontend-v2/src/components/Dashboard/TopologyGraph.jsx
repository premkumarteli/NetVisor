import React, { useMemo, useState } from 'react';
import TopologyGraph3D from './TopologyGraph3D';

const MOCK_NODES = [
  { id: '1', ip: '192.168.1.10', hostname: 'Laptop-01', type: 'laptop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-macbook-line', x: 155, y: 75, pulseSpeed: '2.4s' },
  { id: '2', ip: '192.168.1.15', hostname: 'Android-12', type: 'phone', os: 'Android', risk: 'VPN', color: '#8B5CF6', icon: 'ri-smartphone-line', x: 265, y: 52, pulseSpeed: '1.8s' },
  { id: '3', ip: '192.168.1.20', hostname: 'PC-Office', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', icon: 'ri-computer-line', x: 390, y: 48, pulseSpeed: '3.1s' },
  { id: '4', ip: '192.168.1.25', hostname: 'iPhone', type: 'phone', os: 'iOS', risk: 'High Risk', color: '#EF4444', icon: 'ri-smartphone-line', x: 515, y: 60, pulseSpeed: '1.5s' },
  { id: '5', ip: '192.168.1.30', hostname: 'Server-01', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', icon: 'ri-server-line', x: 615, y: 90, pulseSpeed: '2.8s' },
  { id: '6', ip: '192.168.1.35', hostname: 'SmartTV', type: 'tv', os: 'Others', risk: 'Normal', color: '#60A5FA', icon: 'ri-tv-line', x: 635, y: 175, pulseSpeed: '3.5s' },
  { id: '7', ip: '192.168.1.40', hostname: 'Printer-HQ', type: 'printer', os: 'Others', risk: 'New Device', color: '#10B981', icon: 'ri-printer-line', x: 540, y: 200, pulseSpeed: '2.2s' },
  { id: '8', ip: '192.168.1.45', hostname: 'Security-Cam', type: 'camera', os: 'Linux', risk: 'High Risk', color: '#EF4444', icon: 'ri-camera-line', x: 425, y: 210, pulseSpeed: '2.6s' },
  { id: '9', ip: '192.168.1.50', hostname: 'VPN-Gateway', type: 'server', os: 'Linux', risk: 'VPN', color: '#8B5CF6', icon: 'ri-macbook-line', x: 310, y: 205, pulseSpeed: '2.0s' },
  { id: '10', ip: '192.168.1.55', hostname: 'New-Device', type: 'phone', os: 'Android', risk: 'New Device', color: '#10B981', icon: 'ri-smartphone-line', x: 245, y: 165, pulseSpeed: '1.6s' },
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
  const [viewMode, setViewMode] = useState('3D'); // '3D' | '2D'
  const [isMotionPaused, setIsMotionPaused] = useState(false);

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
      className="glass-card flex flex-col h-[320px] relative overflow-hidden group/card"
      style={{
        contentVisibility: 'auto',
        containIntrinsicSize: 'auto none auto 320px',
      }}
    >
      {/* Dynamic ambient background glow */}
      <div className="absolute -top-24 -left-24 w-72 h-72 bg-blue-500/10 rounded-full blur-3xl pointer-events-none transition-opacity duration-500 group-hover/card:bg-blue-500/15" />
      <div className="absolute -bottom-24 -right-24 w-72 h-72 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none transition-opacity duration-500 group-hover/card:bg-indigo-500/15" />

      {/* Topology Header */}
      <div className="px-4 py-2.5 border-b border-white/[0.08] flex items-center justify-between gap-3 shrink-0 relative z-20">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-[#60A5FA] shadow-[0_0_12px_rgba(96,165,250,0.25)]">
            <i className={`ri-global-line text-sm ${isMotionPaused ? '' : 'animate-spin'}`} style={{ animationDuration: '20s' }}></i>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-[#FFFFFF] tracking-tight">
                Network Topology & Activity
              </h3>
              <span className="flex items-center gap-1 px-1.5 py-0.2 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-[9px] font-bold text-[#34D399]">
                <span className={`w-1.5 h-1.5 rounded-full bg-[#34D399] ${isMotionPaused ? '' : 'animate-pulse'}`} />
                {isMotionPaused ? 'PAUSED' : 'LIVE'}
              </span>
            </div>
            <p className="text-[10px] text-[#9AA3B8]">
              {viewMode === '3D' ? 'Interactive 3D Three.js WebGL Constellation' : '2D Radar Spoke Graph'}
            </p>
          </div>
        </div>

        {/* Center / Right Controls (View Toggle, Filters, Pause) */}
        <div className="flex items-center gap-2.5">
          {/* 3D vs 2D Toggle Pills */}
          <div className="flex items-center p-0.5 rounded-lg bg-white/[0.05] border border-white/[0.08] text-[10.5px]">
            <button
              type="button"
              onClick={() => setViewMode('3D')}
              className={`flex items-center gap-1 px-2 py-0.5 rounded-md transition-all cursor-pointer font-medium ${
                viewMode === '3D'
                  ? 'bg-blue-600/30 text-white shadow-sm ring-1 ring-blue-500/40 text-blue-200'
                  : 'text-[#9AA3B8] hover:text-white'
              }`}
            >
              <i className="ri-box-3-line text-xs"></i>
              3D Matrix
            </button>
            <button
              type="button"
              onClick={() => setViewMode('2D')}
              className={`flex items-center gap-1 px-2 py-0.5 rounded-md transition-all cursor-pointer font-medium ${
                viewMode === '2D'
                  ? 'bg-blue-600/30 text-white shadow-sm ring-1 ring-blue-500/40 text-blue-200'
                  : 'text-[#9AA3B8] hover:text-white'
              }`}
            >
              <i className="ri-radar-line text-xs"></i>
              2D Radar
            </button>
          </div>

          {/* Pause / Play Animation Toggle (WCAG 2.2.2 Compliance) */}
          <button
            type="button"
            onClick={() => setIsMotionPaused((prev) => !prev)}
            className="w-7 h-7 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] flex items-center justify-center text-[#9AA3B8] hover:text-white transition-colors cursor-pointer"
            title={isMotionPaused ? 'Resume live simulation' : 'Pause animation (WCAG 2.2.2)'}
            aria-label={isMotionPaused ? 'Resume animation' : 'Pause animation'}
          >
            <i className={`text-xs ${isMotionPaused ? 'ri-play-fill text-emerald-400' : 'ri-pause-line'}`}></i>
          </button>

          {/* Legend with category filters */}
          <div className="hidden lg:flex items-center gap-1.5 text-[11px] text-[#9AA3B8] pl-1 border-l border-white/[0.08]">
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
                  className={`flex items-center gap-1 px-1.5 py-0.5 rounded-md transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-white/10 text-white shadow-sm ring-1 ring-white/20'
                      : 'hover:text-white hover:bg-white/[0.04]'
                  }`}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full transition-transform"
                    style={{
                      backgroundColor: cat.color,
                      boxShadow: `0 0 6px ${cat.color}`,
                      transform: isSelected ? 'scale(1.2)' : 'scale(1)',
                    }}
                  />
                  <span className="text-[10px]">{cat.label}</span>
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => setActiveFilter('ALL')}
              className="text-[#5E6579] hover:text-white ml-0.5 p-0.5 transition-colors cursor-pointer"
              title="Reset filter"
            >
              <i className="ri-fullscreen-line text-xs"></i>
            </button>
          </div>
        </div>
      </div>

      {/* Main Visualization Body: 3D Hologram vs 2D SVG */}
      <div className="relative flex-1 w-full h-full overflow-hidden select-none">
        {viewMode === '3D' ? (
          <TopologyGraph3D
            devices={devices}
            activity={activity}
            onSelectDevice={onSelectDevice}
            activeFilter={activeFilter}
            isMotionPaused={isMotionPaused}
          />
        ) : (
          <div className="relative w-full h-full">
            <svg
              className="w-full h-full"
              viewBox="0 0 720 250"
              preserveAspectRatio="xMidYMid meet"
            >
              <defs>
                <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.55" />
                  <stop offset="40%" stopColor="#3B82F6" stopOpacity="0.2" />
                  <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
                </radialGradient>

                <filter id="nodeGlow" x="-30%" y="-30%" width="160%" height="160%">
                  <feGaussianBlur stdDeviation="3.5" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>

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
                    {!isMotionPaused && (
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
                    )}

                    {!isMotionPaused && (node.risk === 'High Risk' || node.risk === 'VPN') && (
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
                    {(isHovered || node.risk === 'High Risk') && !isMotionPaused && (
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
                          values={isHovered ? '0.8;0.2;0.8' : '0.4;0.1;0.4'}
                          dur="2s"
                          repeatCount="indefinite"
                        />
                      </circle>
                    )}

                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={r + 3}
                      fill="none"
                      stroke={node.color}
                      strokeWidth="1"
                      strokeOpacity={isHovered ? 0.7 : 0.3}
                      strokeDasharray={node.risk === 'VPN' ? '3 3' : 'none'}
                    />

                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={r}
                      fill="#0C101D"
                      stroke={node.color}
                      strokeWidth={isHovered ? 2.4 : 1.6}
                      style={{ filter: `drop-shadow(0 0 ${isHovered ? 16 : 8}px ${node.color})` }}
                    />

                    <foreignObject x={node.x - 10} y={node.y - 10} width="20" height="20">
                      <div
                        className="w-full h-full flex items-center justify-center text-xs"
                        style={{ color: node.color }}
                      >
                        <i className={node.icon}></i>
                      </div>
                    </foreignObject>

                    <text
                      x={node.x}
                      y={node.y + r + 13}
                      textAnchor="middle"
                      className="text-[10px] font-medium fill-[#9AA3B8] tracking-tight pointer-events-none transition-colors"
                      style={{ fill: isHovered ? '#FFFFFF' : '#9AA3B8' }}
                    >
                      {node.hostname}
                    </text>
                  </g>
                );
              })}

              {/* Central NetVisor Gateway Node */}
              <g className="cursor-pointer" onClick={() => onSelectDevice?.('192.168.1.1')}>
                {!isMotionPaused && (
                  <circle
                    cx="360"
                    cy="125"
                    r="40"
                    fill="none"
                    stroke="#3B82F6"
                    strokeWidth="1.2"
                    strokeOpacity="0.4"
                  >
                    <animate
                      attributeName="r"
                      values="35;50;35"
                      dur="3s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="stroke-opacity"
                      values="0.5;0.1;0.5"
                      dur="3s"
                      repeatCount="indefinite"
                    />
                  </circle>
                )}

                <circle
                  cx="360"
                  cy="125"
                  r="34"
                  fill="none"
                  stroke="#60A5FA"
                  strokeWidth="1"
                  strokeOpacity="0.5"
                  strokeDasharray="4 4"
                />

                <circle
                  cx="360"
                  cy="125"
                  r="28"
                  fill="#0F172A"
                  stroke="#3B82F6"
                  strokeWidth="2.4"
                  style={{ filter: 'drop-shadow(0 0 18px rgba(59,130,246,0.75))' }}
                />

                <foreignObject x="345" y="110" width="30" height="30">
                  <div className="w-full h-full flex items-center justify-center text-base text-[#60A5FA] drop-shadow-[0_0_8px_#60A5FA]">
                    <i className="ri-router-line"></i>
                  </div>
                </foreignObject>
              </g>
            </svg>

            {/* Hover Tooltip Overlay with Glowing Badge in 2D mode */}
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
        )}
      </div>
    </div>
  );
};

export default TopologyGraph;

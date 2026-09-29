import React, { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

// Center Gateway Hub Node (Matching Reference)
const GatewayHubNode = () => {
  return (
    <div className="relative flex flex-col items-center justify-center">
      {/* Radiating Pulse Wave Rings */}
      <div className="absolute w-20 h-20 rounded-full bg-blue-500/10 animate-ping pointer-events-none" style={{ animationDuration: '3.5s' }} />
      <div className="absolute w-14 h-14 rounded-full bg-blue-500/15 border border-blue-500/30 pointer-events-none" />

      {/* Center Icon */}
      <div className="relative w-10 h-10 rounded-full bg-[#10182E] border-2 border-[#3B82F6] shadow-[0_0_20px_rgba(59,130,246,0.45)] flex items-center justify-center text-blue-400 z-10">
        <Handle type="source" position={Position.Top} className="!opacity-0" />
        <Handle type="source" position={Position.Bottom} className="!opacity-0" />
        <Handle type="source" position={Position.Left} className="!opacity-0" />
        <Handle type="source" position={Position.Right} className="!opacity-0" />
        <i className="ri-router-line text-lg"></i>
      </div>
    </div>
  );
};

// Device Endpoint Node (Matching Reference Circular Nodes)
const CircularDeviceNode = ({ data }) => {
  const { device, onSelect } = data;
  const isHighRisk = (Number(device.risk_score) || 0) >= 60 || ['CRITICAL', 'HIGH'].includes(String(device.risk_level).toUpperCase());
  const isVpn = Boolean(device.is_vpn || device.vpn_provider || device.detection_type === 'vpn');
  const isNew = Boolean(device.is_new);

  let toneColor = '#60A5FA'; // Normal (slate/blue)
  if (isHighRisk) {
    toneColor = '#EF4444'; // Red
  } else if (isVpn) {
    toneColor = '#8B5CF6'; // Purple / Violet
  } else if (isNew) {
    toneColor = '#10B981'; // Emerald / Teal
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
  } else if (os.includes('pc') || os.includes('desktop')) {
    icon = 'ri-computer-line';
  }

  return (
    <div
      onClick={() => onSelect?.(device.ip)}
      className="cursor-pointer group flex flex-col items-center justify-center transition-all duration-200 hover:scale-115"
    >
      <Handle type="target" position={Position.Top} className="!opacity-0" />
      <Handle type="target" position={Position.Bottom} className="!opacity-0" />
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <Handle type="target" position={Position.Right} className="!opacity-0" />

      {/* Circular Node Icon Container */}
      <div
        className="w-8 h-8 rounded-full bg-[#0D1222]/90 flex items-center justify-center text-xs shadow-md transition-all duration-200"
        style={{
          border: `1.5px solid ${toneColor}`,
          color: toneColor,
          boxShadow: `0 0 12px ${toneColor}33`,
        }}
      >
        <i className={icon}></i>
      </div>

      {/* Label Tooltip below on hover */}
      <span className="text-[9px] font-medium text-[#9AA3B8] mt-0.5 group-hover:text-white truncate max-w-[70px] bg-black/70 px-1 py-0.2 rounded-full border border-white/5 mono">
        {device.hostname && !['Unknown', 'Unknown-Device', ''].includes(device.hostname)
          ? device.hostname
          : device.ip}
      </span>
    </div>
  );
};

const nodeTypes = {
  gatewayHub: GatewayHubNode,
  circularDevice: CircularDeviceNode,
};

// Observatory-Inspired Topology Empty State
const ObservatoryEmptyState = () => {
  return (
    <div className="absolute inset-0 flex flex-col items-center justify-center p-4 pointer-events-none">
      {/* Concentric Geometric Rings */}
      <div className="relative flex items-center justify-center">
        <div className="w-56 h-56 rounded-full border border-white/[0.04] absolute" />
        <div className="w-40 h-40 rounded-full border border-dashed border-white/[0.06] absolute animate-spin" style={{ animationDuration: '60s' }} />
        <div className="w-24 h-24 rounded-full border border-blue-500/10 absolute" />

        {/* Faint Center Gateway Marker */}
        <div className="w-10 h-10 rounded-full bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.2)]">
          <i className="ri-radar-line text-lg"></i>
        </div>
      </div>

      <div className="mt-4 text-center max-w-xs z-10">
        <h4 className="text-[11px] font-bold uppercase tracking-wider text-[#F1F3F9]">
          Observatory Sensor Active
        </h4>
        <p className="text-[10px] text-[#5E6579] mt-0.5 leading-relaxed">
          Monitoring network interfaces. Constellation maps live as traffic flows.
        </p>
      </div>
    </div>
  );
};

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

  const { nodes, edges } = useMemo(() => {
    if (topDevices.length === 0) {
      return { nodes: [], edges: [] };
    }

    const centerX = 260;
    const centerY = 145;
    const radius = 115;

    const initialNodes = [
      {
        id: 'gateway-hub',
        type: 'gatewayHub',
        position: { x: centerX - 20, y: centerY - 20 },
        data: {},
        draggable: false,
      },
    ];

    const initialEdges = [];
    const angleStep = (2 * Math.PI) / topDevices.length;

    topDevices.forEach((device, index) => {
      // Natural orbit distribution
      const r = radius + ((index % 3) - 1) * 20;
      const angle = index * angleStep - Math.PI / 2;
      const x = Math.round(centerX + r * Math.cos(angle) - 16);
      const y = Math.round(centerY + r * 0.72 * Math.sin(angle) - 16);

      const isHighRisk = (Number(device.risk_score) || 0) >= 60;
      const isVpn = Boolean(device.is_vpn || device.vpn_provider || device.detection_type === 'vpn');
      const strokeColor = isHighRisk ? 'rgba(239, 68, 68, 0.45)' : isVpn ? 'rgba(139, 92, 246, 0.4)' : 'rgba(59, 130, 246, 0.3)';

      initialNodes.push({
        id: `node-${device.ip || index}`,
        type: 'circularDevice',
        position: { x, y },
        data: {
          device,
          onSelect: onSelectDevice,
        },
        draggable: false,
      });

      initialEdges.push({
        id: `edge-gw-${device.ip || index}`,
        source: 'gateway-hub',
        target: `node-${device.ip || index}`,
        animated: isHighRisk || isVpn,
        style: { stroke: strokeColor, strokeWidth: 1.2 },
      });
    });

    return { nodes: initialNodes, edges: initialEdges.slice(0, 24) };
  }, [topDevices, onSelectDevice]);

  return (
    <div
      className="glass-card flex flex-col h-[340px] min-h-[340px] max-h-[340px] relative overflow-hidden"
      style={{
        background: 'rgba(10, 14, 26, 0.78)',
        backdropFilter: 'blur(24px) saturate(160%)',
        WebkitBackdropFilter: 'blur(24px) saturate(160%)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: '0 8px 30px rgba(0, 0, 0, 0.4)',
      }}
    >
      {/* Topology Header matching reference */}
      <div className="px-3.5 py-2.5 border-b border-white/[0.06] flex items-center justify-between gap-3 shrink-0">
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
        </div>
      </div>

      {/* Canvas Area */}
      <div className="flex-1 w-full relative min-h-0">
        {nodes.length === 0 ? (
          <ObservatoryEmptyState />
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={true}
            zoomOnScroll={false}
            panOnScroll={false}
            preventScrolling={false}
            proOptions={{ hideAttribution: true }}
            className="w-full h-full"
          >
            <Background color="rgba(255, 255, 255, 0.03)" gap={20} size={1} />
            <Controls
              showInteractive={false}
              className="!bg-[#0D1222] !border !border-white/10 !rounded-lg !overflow-hidden !scale-75 origin-bottom-left"
            />
          </ReactFlow>
        )}
      </div>
    </div>
  );
};

export default TopologyGraph;

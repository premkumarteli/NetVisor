import React, { useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import StatusBadge from '../Common/StatusBadge';
import { formatByteCount } from '../../utils/presentation';

// Custom Central Gateway Node
const GatewayNode = ({ data }) => {
  return (
    <div className="relative px-4 py-3 rounded-2xl bg-[#111422]/90 border border-blue-500/40 shadow-xl shadow-blue-500/10 flex items-center gap-3 min-w-[170px]">
      <Handle type="source" position={Position.Top} className="!bg-blue-400 !w-2 !h-2" />
      <Handle type="source" position={Position.Bottom} className="!bg-blue-400 !w-2 !h-2" />
      <Handle type="source" position={Position.Left} className="!bg-blue-400 !w-2 !h-2" />
      <Handle type="source" position={Position.Right} className="!bg-blue-400 !w-2 !h-2" />
      <div className="w-8 h-8 rounded-xl bg-blue-500/20 text-[#60A5FA] flex items-center justify-center font-bold">
        <i className="ri-radar-line text-lg"></i>
      </div>
      <div>
        <div className="text-xs font-bold text-[#F1F3F9] tracking-tight">{data.label || 'Gateway Core'}</div>
        <div className="text-[10px] text-[#9AA3B8] mono">Active Sensor Hub</div>
      </div>
    </div>
  );
};

// Custom Device Endpoint Node
const DeviceNode = ({ data }) => {
  const { device, onSelect } = data;
  const isHighRisk = (Number(device.risk_score) || 0) >= 60 || ['CRITICAL', 'HIGH'].includes(String(device.risk_level).toUpperCase());
  const isVpn = Boolean(device.is_vpn || device.vpn_provider || device.detection_type === 'vpn');
  const isNew = Boolean(device.is_new);

  let toneColor = '#34D399'; // Normal green
  let badgeLabel = 'NORMAL';
  let badgeTone = 'green';

  if (isHighRisk) {
    toneColor = '#FB7185';
    badgeLabel = 'HIGH RISK';
    badgeTone = 'rose';
  } else if (isVpn) {
    toneColor = '#A78BFA';
    badgeLabel = 'VPN';
    badgeTone = 'violet';
  } else if (isNew) {
    toneColor = '#54C8E8';
    badgeLabel = 'NEW';
    badgeTone = 'teal';
  }

  return (
    <div
      onClick={() => onSelect?.(device.ip)}
      className="cursor-pointer group relative px-3 py-2.5 rounded-xl bg-[#0D101D]/90 border transition-all duration-200 hover:scale-105 shadow-lg min-w-[150px]"
      style={{
        borderColor: `${toneColor}40`,
        boxShadow: `0 4px 20px ${toneColor}15`,
      }}
    >
      <Handle type="target" position={Position.Top} className="!bg-slate-400 !w-1.5 !h-1.5" />
      <Handle type="target" position={Position.Bottom} className="!bg-slate-400 !w-1.5 !h-1.5" />
      <Handle type="target" position={Position.Left} className="!bg-slate-400 !w-1.5 !h-1.5" />
      <Handle type="target" position={Position.Right} className="!bg-slate-400 !w-1.5 !h-1.5" />

      <div className="flex items-center justify-between gap-2 mb-1.5">
        <span className="text-[11px] font-bold text-[#F1F3F9] truncate max-w-[90px]">
          {device.hostname && !['Unknown', 'Unknown-Device', ''].includes(device.hostname)
            ? device.hostname
            : `Dev ${device.ip}`}
        </span>
        <StatusBadge tone={badgeTone}>{badgeLabel}</StatusBadge>
      </div>

      <div className="flex items-center justify-between text-[10px] text-[#9AA3B8]">
        <span className="mono truncate">{device.ip}</span>
        {device.bandwidth_bytes > 0 && (
          <span className="mono font-semibold text-[#54C8E8]">
            {formatByteCount(device.bandwidth_bytes)}
          </span>
        )}
      </div>
    </div>
  );
};

const nodeTypes = {
  gatewayNode: GatewayNode,
  deviceNode: DeviceNode,
};

// Embedded Trust Status Row (Section 3)
export const TrustStatusHeader = ({ wsStatus, agentsSummary, bandwidthStr, inspectionCoverage }) => {
  const isOnline = wsStatus === 'connected';

  return (
    <div className="flex items-center flex-wrap gap-4 py-2 px-3 rounded-xl bg-white/[0.03] border border-white/5 text-xs text-[#9AA3B8]">
      {/* Sensor streaming */}
      <div className="flex items-center gap-2">
        <span
          className={`w-2 h-2 rounded-full ${
            isOnline ? 'bg-[#34D399] shadow-[0_0_8px_#34D399]' : 'bg-[#FB7185]'
          }`}
        />
        <span>Sensor:</span>
        <strong className="text-[#F1F3F9]">{isOnline ? 'Streaming' : 'Connecting'}</strong>
      </div>

      <div className="h-3 w-px bg-white/10" />

      {/* Agent Health */}
      <div className="flex items-center gap-2">
        <i className="ri-cpu-line text-[#60A5FA]"></i>
        <span>Agents:</span>
        <strong className="text-[#F1F3F9] tabular-nums">
          {agentsSummary?.online ?? 0}/{agentsSummary?.total ?? 0} online
        </strong>
      </div>

      <div className="h-3 w-px bg-white/10" />

      {/* Ingestion Volume */}
      <div className="flex items-center gap-2">
        <i className="ri-pulse-line text-[#54C8E8]"></i>
        <span>Volume:</span>
        <strong className="text-[#F1F3F9] mono">{bandwidthStr || '0 B/s'}</strong>
      </div>

      <div className="h-3 w-px bg-white/10" />

      {/* Inspection Coverage */}
      <div className="flex items-center gap-2">
        <i className="ri-shield-check-line text-[#34D399]"></i>
        <span>Coverage:</span>
        <strong className="text-[#F1F3F9] tabular-nums">{inspectionCoverage ?? 100}%</strong>
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
  // Cap at top 14 devices by risk score or activity
  const topDevices = useMemo(() => {
    if (!Array.isArray(devices) || devices.length === 0) return [];
    return [...devices]
      .sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0))
      .slice(0, 14);
  }, [devices]);

  // Initial one-time layout computation (Static physics after initial render)
  const { nodes, edges } = useMemo(() => {
    if (topDevices.length === 0) {
      return { nodes: [], edges: [] };
    }

    const centerX = 380;
    const centerY = 260;
    const radius = 210;

    const initialNodes = [
      {
        id: 'gateway-core',
        type: 'gatewayNode',
        position: { x: centerX - 85, y: centerY - 25 },
        data: { label: 'NetVisor Gateway' },
        draggable: false,
      },
    ];

    const initialEdges = [];
    const angleStep = (2 * Math.PI) / topDevices.length;

    topDevices.forEach((device, index) => {
      // Position evenly in a circle around gateway
      const angle = index * angleStep - Math.PI / 2;
      const x = Math.round(centerX + radius * Math.cos(angle) - 75);
      const y = Math.round(centerY + radius * Math.sin(angle) - 25);

      const isHighRisk = (Number(device.risk_score) || 0) >= 60;
      const edgeColor = isHighRisk ? 'rgba(251, 113, 133, 0.4)' : 'rgba(96, 165, 250, 0.25)';

      initialNodes.push({
        id: `node-${device.ip || index}`,
        type: 'deviceNode',
        position: { x, y },
        data: {
          device,
          onSelect: onSelectDevice,
        },
        draggable: false,
      });

      // Edge from gateway to device
      initialEdges.push({
        id: `edge-gw-${device.ip || index}`,
        source: 'gateway-core',
        target: `node-${device.ip || index}`,
        animated: isHighRisk,
        style: { stroke: edgeColor, strokeWidth: isHighRisk ? 2 : 1 },
      });
    });

    // Add inter-device edges based on recent activity, capped at 30 edges total
    const deviceIps = new Set(topDevices.map((d) => d.ip));
    let extraEdgeCount = 0;

    if (Array.isArray(activity)) {
      activity.forEach((act, actIdx) => {
        if (initialEdges.length >= 30) return;
        if (
          act.src_ip &&
          act.dst_ip &&
          act.src_ip !== act.dst_ip &&
          deviceIps.has(act.src_ip) &&
          deviceIps.has(act.dst_ip)
        ) {
          const edgeId = `edge-flow-${act.src_ip}-${act.dst_ip}-${actIdx}`;
          if (!initialEdges.some((e) => e.id === edgeId)) {
            initialEdges.push({
              id: edgeId,
              source: `node-${act.src_ip}`,
              target: `node-${act.dst_ip}`,
              animated: true,
              style: { stroke: 'rgba(84, 200, 232, 0.3)', strokeWidth: 1.2 },
            });
            extraEdgeCount++;
          }
        }
      });
    }

    return { nodes: initialNodes, edges: initialEdges.slice(0, 30) };
  }, [topDevices, activity, onSelectDevice]);

  return (
    <div className="glass-card flex flex-col h-full min-h-[580px] relative overflow-hidden">
      {/* Topology Header with Embedded Trust Status */}
      <div className="p-5 border-b border-white/10 flex flex-col gap-3">
        <div className="flex items-center justify-between gap-4">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[#9AA3B8]">
              Live Network Fabric
            </span>
            <h2 className="text-lg font-bold text-[#F1F3F9] tracking-tight">
              Topology & Connection Mesh
            </h2>
          </div>

          {/* Legend */}
          <div className="hidden sm:flex items-center gap-3 text-[11px] font-semibold text-[#9AA3B8]">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#34D399]" /> Normal
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#A78BFA]" /> VPN
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#FB7185]" /> High Risk
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#54C8E8]" /> New
            </span>
          </div>
        </div>

        {/* Embedded Trust Status (Section 3) */}
        <TrustStatusHeader {...trustStatusProps} />
      </div>

      {/* Canvas Area */}
      <div className="flex-1 w-full h-[460px] relative">
        {nodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center p-8 text-center">
            <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-2xl text-[#9AA3B8] mb-3">
              <i className="ri-radar-line"></i>
            </div>
            <h3 className="text-base font-bold text-[#F1F3F9] mb-1">No Active Connections</h3>
            <p className="text-xs text-[#5E6579] max-w-sm">
              The topology graph will materialize once endpoint traffic or sensor heartbeats register on the gateway.
            </p>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.25 }}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={true}
            zoomOnScroll={false}
            panOnScroll={false}
            preventScrolling={false}
            proOptions={{ hideAttribution: true }}
            className="w-full h-full"
          >
            <Background color="rgba(255, 255, 255, 0.05)" gap={24} size={1} />
            <Controls
              showInteractive={false}
              className="!bg-[#111422] !border !border-white/10 !rounded-xl !overflow-hidden"
            />
          </ReactFlow>
        )}
      </div>
    </div>
  );
};

export default TopologyGraph;

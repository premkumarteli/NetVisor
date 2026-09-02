import React, { useState } from 'react';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_VPN_TUNNELS } from '../sampleData/mockDatabase';

export const VpnPage = () => {
  const [inspectData, setInspectData] = useState(null);

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Encrypted Tunnels</span>
        <h2 className="text-2xl font-bold text-slate-100">VPN Session Telemetry</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Encrypted Tunnel Cards with Live Throughput & Cipher Suite Verification.
        </p>
      </div>

      <SingleRowList emptyTitle="No active VPN tunnels">
        {MOCK_VPN_TUNNELS.map((tunnel) => (
          <SingleRowCard
            key={tunnel.id}
            icon="ri-shield-keyhole-line"
            iconBg="bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
            title={`VPN Session #${tunnel.id} - ${tunnel.user}`}
            subtitle={`Client IP: ${tunnel.client_ip} &rarr; Tunnel IP: ${tunnel.assigned_vpn_ip} &bull; Protocol: ${tunnel.protocol}`}
            tags={[tunnel.cipher, tunnel.connected_at]}
            statusBadge={<StatusBadge tone="success">{tunnel.status}</StatusBadge>}
            metrics={[
              { label: 'Tunnel In', value: tunnel.bytes_in, color: 'text-cyan-300' },
              { label: 'Tunnel Out', value: tunnel.bytes_out, color: 'text-emerald-400' }
            ]}
            actions={[
              {
                label: 'Inspect Tunnel',
                icon: 'ri-search-eye-line',
                variant: 'cyan',
                onClick: () => setInspectData(tunnel)
              },
              {
                label: 'Disconnect',
                icon: 'ri-shut-down-line',
                variant: 'danger',
                onClick: () => alert(`Terminated VPN session ${tunnel.id}`)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-1 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">Cipher Encryption Suite:</strong> {tunnel.cipher}</p>
                <p><strong className="text-slate-400">Assigned Virtual Gateway IP:</strong> {tunnel.assigned_vpn_ip}</p>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`VPN Tunnel Session: ${inspectData?.id}`}
        data={inspectData}
      />
    </div>
  );
};

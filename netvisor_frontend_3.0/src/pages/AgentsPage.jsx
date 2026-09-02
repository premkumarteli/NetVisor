import React, { useState } from 'react';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_AGENTS } from '../sampleData/mockDatabase';

export const AgentsPage = () => {
  const [inspectData, setInspectData] = useState(null);

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Node Management</span>
        <h2 className="text-2xl font-bold text-slate-100">Managed Agents & Sensor Nodes</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Endpoint Agent Cards with mTLS Certificate Expiry & Live System Resource Gauges.
        </p>
      </div>

      <SingleRowList emptyTitle="No active agents enrolled">
        {MOCK_AGENTS.map((agent) => (
          <SingleRowCard
            key={agent.id}
            icon="ri-cpu-line"
            iconBg="bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
            title={`${agent.hostname} (${agent.ip})`}
            subtitle={`Agent ID: ${agent.id} &bull; OS: ${agent.os} &bull; Version: ${agent.version}`}
            tags={[agent.browsers, agent.privacy_guard]}
            statusBadge={<StatusBadge tone={agent.status}>{agent.status}</StatusBadge>}
            metrics={[
              { label: 'CPU Usage', value: agent.cpu_usage, color: 'text-cyan-300' },
              { label: 'RAM Usage', value: agent.ram_usage, color: 'text-purple-400' }
            ]}
            actions={[
              {
                label: 'Inspect Telemetry',
                icon: 'ri-search-eye-line',
                variant: 'cyan',
                onClick: () => setInspectData(agent)
              },
              {
                label: 'Restart Service',
                icon: 'ri-restart-line',
                variant: 'warning',
                onClick: () => alert(`Triggered remote service restart for ${agent.hostname}`)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-1 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">mTLS Security Certificate:</strong> {agent.mtls_cert}</p>
                <p><strong className="text-slate-400">Monitored Process Scope:</strong> {agent.browsers}</p>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`Agent Telemetry: ${inspectData?.hostname}`}
        data={inspectData}
      />
    </div>
  );
};

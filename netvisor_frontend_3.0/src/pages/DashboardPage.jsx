import React, { useState } from 'react';
import { MetricCard } from '../components/UI/MetricCard';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { 
  MOCK_SUMMARY_STATS, 
  MOCK_DEVICES, 
  MOCK_THREATS, 
  MOCK_TRAFFIC_FLOWS 
} from '../sampleData/mockDatabase';

export const DashboardPage = () => {
  const [inspectModalData, setInspectModalData] = useState(null);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">NetVisor 3.0 Workspace</span>
        <h2 className="text-2xl font-bold text-slate-100">Analyst Command Overview</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          High-density telemetry dashboard with instant Single-Row Action Functions.
        </p>
      </div>

      {/* Top Metric Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Online Assets"
          value={`${MOCK_SUMMARY_STATS.active_devices} / ${MOCK_SUMMARY_STATS.total_devices}`}
          meta="Gateway ARP + Agent Verified"
          icon="ri-macbook-line"
          accentColor="from-cyan-500/20 to-blue-600/10"
        />
        <MetricCard
          title="Flows (24h Window)"
          value={MOCK_SUMMARY_STATS.flows_24h.toLocaleString()}
          meta="Ingested via Pooled Lock Pipeline"
          icon="ri-exchange-box-line"
          accentColor="from-blue-500/20 to-purple-600/10"
        />
        <MetricCard
          title="Active Security Threats"
          value={MOCK_SUMMARY_STATS.high_threats}
          meta={`${MOCK_SUMMARY_STATS.medium_threats} medium signal sessions`}
          icon="ri-alarm-warning-line"
          accentColor="from-rose-500/20 to-amber-600/10"
        />
        <MetricCard
          title="Live Throughput"
          value={MOCK_SUMMARY_STATS.bandwidth_formatted}
          meta="Hotspot Interface Bandwidth"
          icon="ri-pulse-line"
          accentColor="from-emerald-500/20 to-teal-600/10"
        />
      </div>

      {/* Priority Single-Row Threat Stream */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <i className="ri-alarm-warning-fill text-rose-400"></i>
            Active Security Signals (Single-Row Action Stream)
          </h3>
          <span className="text-xs font-mono-code text-slate-400">3 Priority Items</span>
        </div>

        <SingleRowList>
          {MOCK_THREATS.map((threat) => (
            <SingleRowCard
              key={threat.id}
              icon="ri-error-warning-line"
              iconBg={threat.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : 'bg-amber-500/20 text-amber-400 border-amber-500/30'}
              title={threat.title}
              subtitle={`${threat.device} &bull; ${threat.summary}`}
              tags={[threat.engine, threat.timestamp]}
              statusBadge={<StatusBadge tone={threat.severity}>{threat.severity}</StatusBadge>}
              metrics={[
                { label: 'Risk Score', value: `${threat.score}%`, color: 'text-rose-400' }
              ]}
              actions={[
                {
                  label: 'Investigate',
                  icon: 'ri-search-eye-line',
                  variant: 'cyan',
                  onClick: () => setInspectModalData(threat)
                },
                {
                  label: 'Isolate Asset',
                  icon: 'ri-shield-cross-line',
                  variant: 'danger',
                  onClick: () => alert(`Isolated device: ${threat.device}`)
                }
              ]}
              expandableContent={
                <div className="text-xs space-y-2 text-slate-300 font-mono-code">
                  <p><strong className="text-cyan-400">Engine Recommendation:</strong> {threat.recommendation}</p>
                  <p><strong className="text-slate-400">Status:</strong> {threat.status}</p>
                </div>
              }
            />
          ))}
        </SingleRowList>
      </div>

      {/* Recent Devices Single-Row List */}
      <div className="space-y-3 pt-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <i className="ri-macbook-line text-cyan-400"></i>
            Monitored Assets (Single-Row Functions)
          </h3>
        </div>

        <SingleRowList>
          {MOCK_DEVICES.slice(0, 3).map((dev) => (
            <SingleRowCard
              key={dev.id}
              icon="ri-computer-line"
              iconBg="bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
              title={`${dev.hostname} (${dev.ip})`}
              subtitle={`${dev.vendor} &bull; ${dev.os_family} &bull; MAC: ${dev.mac}`}
              tags={[dev.management_mode === 'managed' ? 'Agent Endpoint' : 'BYOD Gateway', dev.top_application]}
              statusBadge={<StatusBadge tone={dev.status}>{dev.status}</StatusBadge>}
              metrics={[
                { label: 'Data', value: dev.bytes_transferred, color: 'text-cyan-300' },
                { label: 'Risk', value: `${dev.risk_score}%`, color: dev.risk_score > 70 ? 'text-rose-400' : 'text-emerald-400' }
              ]}
              actions={[
                {
                  label: 'Inspect',
                  icon: 'ri-line-chart-line',
                  variant: 'cyan',
                  onClick: () => setInspectModalData(dev)
                },
                {
                  label: 'Quarantine',
                  icon: 'ri-lock-line',
                  variant: 'warning',
                  onClick: () => alert(`Quarantined ${dev.hostname}`)
                }
              ]}
              expandableContent={
                <div className="text-xs space-y-1 font-mono-code text-slate-300">
                  <p><strong className="text-cyan-400">Identity Confidence:</strong> {dev.confidence}</p>
                  <p><strong className="text-slate-400">Last Telemetry Check:</strong> {dev.last_seen}</p>
                </div>
              }
            />
          ))}
        </SingleRowList>
      </div>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectModalData)}
        onClose={() => setInspectModalData(null)}
        title={inspectModalData?.title || inspectModalData?.hostname || "Single Row Evidence"}
        data={inspectModalData}
      />
    </div>
  );
};

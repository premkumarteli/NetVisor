import React, { useState } from 'react';
import { FilterBar } from '../components/UI/FilterBar';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_THREATS } from '../sampleData/mockDatabase';

export const ThreatsPage = () => {
  const [search, setSearch] = useState('');
  const [inspectData, setInspectData] = useState(null);

  const filteredThreats = MOCK_THREATS.filter((t) =>
    t.title.toLowerCase().includes(search.toLowerCase()) ||
    t.device.toLowerCase().includes(search.toLowerCase()) ||
    t.engine.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-rose-400 font-semibold tracking-wider">Security Intelligence</span>
        <h2 className="text-2xl font-bold text-slate-100">Detection Engine Alerts</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Threat Cards for Real-Time Anomaly, Threat Intel & DPI Inspection Triggers.
        </p>
      </div>

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        placeholder="Filter threat title, target device, engine name..."
      />

      <SingleRowList emptyTitle="No security threats detected">
        {filteredThreats.map((threat) => (
          <SingleRowCard
            key={threat.id}
            icon="ri-alarm-warning-line"
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
                label: 'Investigate Signal',
                icon: 'ri-search-eye-line',
                variant: 'cyan',
                onClick: () => setInspectData(threat)
              },
              {
                label: 'Dismiss Alert',
                icon: 'ri-check-line',
                variant: 'warning',
                onClick: () => alert(`Dismissed threat alert ${threat.id}`)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-2 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">Mitigation Strategy:</strong> {threat.recommendation}</p>
                <p><strong className="text-slate-400">Current Alert Status:</strong> {threat.status}</p>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`Threat Analysis: ${inspectData?.title}`}
        data={inspectData}
      />
    </div>
  );
};

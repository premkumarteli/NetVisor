import React, { useState } from 'react';
import { FilterBar } from '../components/UI/FilterBar';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_APPLICATIONS } from '../sampleData/mockDatabase';

export const ApplicationsPage = () => {
  const [search, setSearch] = useState('');
  const [inspectData, setInspectData] = useState(null);

  const filteredApps = MOCK_APPLICATIONS.filter((app) => 
    app.name.toLowerCase().includes(search.toLowerCase()) ||
    app.domain.toLowerCase().includes(search.toLowerCase()) ||
    app.category.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Application Intelligence</span>
        <h2 className="text-2xl font-bold text-slate-100">Discovered Applications</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Application Registry with Policy Enforcement & Heuristic Discovery Controls.
        </p>
      </div>

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        placeholder="Filter application name, domain, category..."
      />

      <SingleRowList emptyTitle="No applications found">
        {filteredApps.map((app) => (
          <SingleRowCard
            key={app.id}
            icon="ri-apps-2-line"
            iconBg={app.risk_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'}
            title={`${app.name} (${app.domain})`}
            subtitle={`Category: ${app.category} &bull; Discovery Source: ${app.source_layer}`}
            tags={[app.policy_status]}
            statusBadge={<StatusBadge tone={app.risk_level}>{app.risk_level}</StatusBadge>}
            metrics={[
              { label: 'Devices Active', value: `${app.devices_using} Devices`, color: 'text-slate-200' },
              { label: 'Total Volume', value: app.total_volume, color: 'text-cyan-300' }
            ]}
            actions={[
              {
                label: 'Inspect App',
                icon: 'ri-search-line',
                variant: 'cyan',
                onClick: () => setInspectData(app)
              },
              {
                label: 'Enforce Policy',
                icon: 'ri-shield-keyhole-line',
                variant: 'warning',
                onClick: () => alert(`Updated policy status for ${app.name}`)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-1 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">Classification Confidence:</strong> {app.confidence * 100}%</p>
                <p><strong className="text-slate-400">Current Status:</strong> {app.policy_status}</p>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`Application Metadata: ${inspectData?.name}`}
        data={inspectData}
      />
    </div>
  );
};

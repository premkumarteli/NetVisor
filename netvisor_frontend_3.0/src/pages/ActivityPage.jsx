import React, { useState } from 'react';
import { FilterBar } from '../components/UI/FilterBar';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_TRAFFIC_FLOWS } from '../sampleData/mockDatabase';

export const ActivityPage = () => {
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('ALL');
  const [inspectData, setInspectData] = useState(null);

  const categories = [
    { key: 'ALL', label: 'All Sessions', count: MOCK_TRAFFIC_FLOWS.length },
    { key: 'CRITICAL', label: 'Critical / High Signal', count: MOCK_TRAFFIC_FLOWS.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length },
    { key: 'LOW', label: 'Normal Traffic', count: MOCK_TRAFFIC_FLOWS.filter(f => f.severity === 'LOW').length }
  ];

  const filteredFlows = MOCK_TRAFFIC_FLOWS.filter((flow) => {
    const matchesSearch = 
      flow.application.toLowerCase().includes(search.toLowerCase()) ||
      flow.domain.toLowerCase().includes(search.toLowerCase()) ||
      flow.src_ip.includes(search) ||
      flow.dst_ip.includes(search);
    
    if (!matchesSearch) return false;
    if (activeCategory === 'CRITICAL') return flow.severity === 'CRITICAL' || flow.severity === 'HIGH';
    if (activeCategory === 'LOW') return flow.severity === 'LOW';
    return true;
  });

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Session Investigation</span>
        <h2 className="text-2xl font-bold text-slate-100">Live Traffic Activity</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Classified Traffic Flow Stream with Instant Inspection & Protocol Analytics.
        </p>
      </div>

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        categories={categories}
        activeCategory={activeCategory}
        onCategoryChange={setActiveCategory}
        placeholder="Filter by application, domain, source IP, or destination..."
      />

      <SingleRowList emptyTitle="No traffic flows match filter">
        {filteredFlows.map((flow) => (
          <SingleRowCard
            key={flow.id}
            icon="ri-exchange-line"
            iconBg={flow.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'}
            title={`${flow.application} (${flow.domain})`}
            subtitle={`Source: ${flow.src_device} (${flow.src_ip}) &rarr; Target: ${flow.dst_ip}`}
            tags={[flow.protocol, flow.category, flow.direction]}
            statusBadge={<StatusBadge tone={flow.severity}>{flow.severity}</StatusBadge>}
            metrics={[
              { label: 'Volume', value: flow.formatted_volume, color: 'text-cyan-300' },
              { label: 'Confidence', value: flow.confidence.split(' ')[0], color: 'text-emerald-400' }
            ]}
            actions={[
              {
                label: 'Inspect Flow',
                icon: 'ri-search-line',
                variant: 'cyan',
                onClick: () => setInspectData(flow)
              },
              {
                label: 'Filter Source IP',
                icon: 'ri-filter-3-line',
                variant: 'warning',
                onClick: () => setSearch(flow.src_ip)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-1 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">Truth & Verification:</strong> {flow.confidence}</p>
                <p><strong className="text-slate-400">Timestamp:</strong> {flow.timestamp}</p>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`Flow Evidence: ${inspectData?.application}`}
        data={inspectData}
      />
    </div>
  );
};

import React, { useState } from 'react';
import { FilterBar } from '../components/UI/FilterBar';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_DEVICES } from '../sampleData/mockDatabase';

export const DevicesPage = () => {
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('ALL');
  const [inspectData, setInspectData] = useState(null);

  const categories = [
    { key: 'ALL', label: 'All Devices', count: MOCK_DEVICES.length },
    { key: 'MANAGED', label: 'Managed Agent', count: MOCK_DEVICES.filter(d => d.management_mode === 'managed').length },
    { key: 'BYOD', label: 'BYOD Gateway', count: MOCK_DEVICES.filter(d => d.management_mode === 'gateway_only').length }
  ];

  const filteredDevices = MOCK_DEVICES.filter((dev) => {
    const matchesSearch = 
      dev.hostname.toLowerCase().includes(search.toLowerCase()) ||
      dev.ip.includes(search) ||
      dev.mac.toLowerCase().includes(search.toLowerCase()) ||
      dev.vendor.toLowerCase().includes(search.toLowerCase());
    
    if (!matchesSearch) return false;
    if (activeCategory === 'MANAGED') return dev.management_mode === 'managed';
    if (activeCategory === 'BYOD') return dev.management_mode === 'gateway_only';
    return true;
  });

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Asset Inventory</span>
        <h2 className="text-2xl font-bold text-slate-100">Discovered Network Devices</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Actionable Asset Cards for Managed Endpoints & BYOD Sensor Assets.
        </p>
      </div>

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        categories={categories}
        activeCategory={activeCategory}
        onCategoryChange={setActiveCategory}
        placeholder="Search hostname, IP, MAC address, vendor..."
      />

      <SingleRowList emptyTitle="No devices found matching query">
        {filteredDevices.map((dev) => (
          <SingleRowCard
            key={dev.id}
            icon="ri-macbook-line"
            iconBg={dev.risk_score > 70 ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'}
            title={`${dev.hostname} (${dev.ip})`}
            subtitle={`${dev.vendor} &bull; ${dev.os_family} &bull; MAC: ${dev.mac}`}
            tags={[dev.device_type, dev.management_mode === 'managed' ? 'Agent Managed' : 'BYOD Asset']}
            statusBadge={<StatusBadge tone={dev.status}>{dev.status}</StatusBadge>}
            metrics={[
              { label: 'Data Output', value: dev.bytes_transferred, color: 'text-cyan-300' },
              { label: 'Risk Score', value: `${dev.risk_score}%`, color: dev.risk_score > 70 ? 'text-rose-400' : 'text-emerald-400' }
            ]}
            actions={[
              {
                label: 'Inspect Asset',
                icon: 'ri-search-eye-line',
                variant: 'cyan',
                onClick: () => setInspectData(dev)
              },
              {
                label: 'Quarantine',
                icon: 'ri-shield-cross-line',
                variant: 'danger',
                onClick: () => alert(`Quarantined asset ${dev.hostname} (${dev.ip})`)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-1 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">Identity Explanation:</strong> {dev.confidence}</p>
                <p><strong className="text-slate-400">Top Application Signal:</strong> {dev.top_application}</p>
                <p><strong className="text-slate-400">Last Telemetry Active:</strong> {dev.last_seen}</p>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`Asset Diagnostics: ${inspectData?.hostname}`}
        data={inspectData}
      />
    </div>
  );
};

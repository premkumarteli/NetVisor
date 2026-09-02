import React, { useState } from 'react';
import { FilterBar } from '../components/UI/FilterBar';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_DPI_EVIDENCE } from '../sampleData/mockDatabase';

export const DpiInspectionPage = () => {
  const [search, setSearch] = useState('');
  const [inspectData, setInspectData] = useState(null);

  const filteredEvidence = MOCK_DPI_EVIDENCE.filter((e) =>
    e.domain.toLowerCase().includes(search.toLowerCase()) ||
    e.path.toLowerCase().includes(search.toLowerCase()) ||
    e.device.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Browser Evidence Workspace</span>
        <h2 className="text-2xl font-bold text-slate-100">Deep Packet Inspection (DPI) Evidence</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Web Evidence Cards with Automatic Sensitive Payload Redaction & SNI Tracing.
        </p>
      </div>

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        placeholder="Search domain, URL path, process name, device..."
      />

      <SingleRowList emptyTitle="No DPI evidence records found">
        {filteredEvidence.map((ev) => (
          <SingleRowCard
            key={ev.id}
            icon="ri-global-line"
            iconBg="bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
            title={`${ev.http_method} ${ev.domain}${ev.path}`}
            subtitle={`Device: ${ev.device} &bull; Process: ${ev.process} &bull; Status: ${ev.status_code}`}
            tags={[ev.content_type, ev.redaction_status]}
            statusBadge={<StatusBadge tone="success">Verified DPI</StatusBadge>}
            metrics={[
              { label: 'Confidence', value: ev.confidence, color: 'text-emerald-400' }
            ]}
            actions={[
              {
                label: 'View Payload',
                icon: 'ri-file-code-line',
                variant: 'cyan',
                onClick: () => setInspectData(ev)
              },
              {
                label: 'Redact Snippet',
                icon: 'ri-eye-off-line',
                variant: 'warning',
                onClick: () => alert(`Snippet payload redacted for record ${ev.id}`)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-2 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">Captured Payload Snippet:</strong></p>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
                  {ev.snippet}
                </div>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`DPI Web Evidence Payload: ${inspectData?.domain}`}
        data={inspectData}
      />
    </div>
  );
};

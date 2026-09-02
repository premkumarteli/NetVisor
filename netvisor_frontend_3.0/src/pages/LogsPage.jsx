import React, { useState } from 'react';
import { FilterBar } from '../components/UI/FilterBar';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_LOGS } from '../sampleData/mockDatabase';

export const LogsPage = () => {
  const [search, setSearch] = useState('');
  const [inspectData, setInspectData] = useState(null);

  const filteredLogs = MOCK_LOGS.filter((l) =>
    l.module.toLowerCase().includes(search.toLowerCase()) ||
    l.message.toLowerCase().includes(search.toLowerCase()) ||
    l.level.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">System Audit</span>
        <h2 className="text-2xl font-bold text-slate-100">Audit & Diagnostic Logs</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row System Event Items with JSON Accordion Payload Drawers & Module Filtering.
        </p>
      </div>

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        placeholder="Filter log message, system module, log level..."
      />

      <SingleRowList emptyTitle="No system logs found">
        {filteredLogs.map((log) => (
          <SingleRowCard
            key={log.id}
            icon="ri-terminal-box-line"
            iconBg={log.level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : log.level === 'WARN' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'}
            title={`[${log.module}] ${log.message}`}
            subtitle={`Logged At: ${log.timestamp}`}
            tags={[log.module]}
            statusBadge={<StatusBadge tone={log.level}>{log.level}</StatusBadge>}
            metrics={[]}
            actions={[
              {
                label: 'View JSON',
                icon: 'ri-code-line',
                variant: 'cyan',
                onClick: () => setInspectData(log)
              },
              {
                label: 'Copy Log',
                icon: 'ri-file-copy-line',
                variant: 'warning',
                onClick: () => alert(`Copied log: ${log.message}`)
              }
            ]}
            expandableContent={
              <div className="text-xs font-mono-code text-cyan-300 bg-slate-900 p-2.5 rounded border border-slate-800">
                <pre>{JSON.stringify(log, null, 2)}</pre>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`Audit Log Record: ${inspectData?.id}`}
        data={inspectData}
      />
    </div>
  );
};

import React, { useState } from 'react';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';

export const SettingsPage = () => {
  const [configs, setConfigs] = useState([
    { id: 'cfg-1', key: 'NETVISOR_GATEWAY_HOTSPOT', title: 'Hotspot Gateway Ingestion', value: 'Enabled', desc: 'Passively monitors BYOD assets connected via Windows Mobile Hotspot adapter.', type: 'toggle' },
    { id: 'cfg-2', key: 'NETVISOR_TRANSPARENT_DPI_REDACTION', title: 'Transparent DPI Sensitive Data Redaction', value: 'Active', desc: 'Automatically strips passwords, auth tokens, and PII from browser inspection evidence.', type: 'toggle' },
    { id: 'cfg-3', key: 'NETVISOR_MTLS_REVOCATION_CHECK', title: 'mTLS Agent Certificate Revocation Checks', value: 'Strict Non-Blocking', desc: 'Enforces CRL checks on agent enrollment nonces.', type: 'toggle' },
    { id: 'cfg-4', key: 'NETVISOR_ANOMALY_BURST_THRESHOLD', title: 'Anomaly Packet Burst Threshold', value: '4,000 pkts/15s', desc: 'Sensitivity limit for triggering high-volume flow burst threat alerts.', type: 'text' }
  ]);

  const toggleConfig = (id) => {
    setConfigs(configs.map(c => {
      if (c.id === id) {
        const nextVal = c.value === 'Enabled' ? 'Disabled' : c.value === 'Active' ? 'Disabled' : 'Enabled';
        return { ...c, value: nextVal };
      }
      return c;
    }));
  };

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Workspace Configuration</span>
        <h2 className="text-2xl font-bold text-slate-100">NetVisor System Settings</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row Setting Controls for Gateway Ingestion, DPI Redaction & Detection Sensitivity.
        </p>
      </div>

      <SingleRowList>
        {configs.map((cfg) => (
          <SingleRowCard
            key={cfg.id}
            icon="ri-settings-3-line"
            iconBg="bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
            title={cfg.title}
            subtitle={`${cfg.key} &bull; ${cfg.desc}`}
            tags={['System Key']}
            statusBadge={<StatusBadge tone={cfg.value === 'Disabled' ? 'danger' : 'success'}>{cfg.value}</StatusBadge>}
            metrics={[]}
            actions={[
              {
                label: cfg.value === 'Disabled' ? 'Enable' : 'Toggle',
                icon: 'ri-toggle-line',
                variant: cfg.value === 'Disabled' ? 'success' : 'cyan',
                onClick: () => toggleConfig(cfg.id)
              },
              {
                label: 'Save Setting',
                icon: 'ri-save-3-line',
                variant: 'warning',
                onClick: () => alert(`Saved configuration setting ${cfg.key}`)
              }
            ]}
          />
        ))}
      </SingleRowList>
    </div>
  );
};

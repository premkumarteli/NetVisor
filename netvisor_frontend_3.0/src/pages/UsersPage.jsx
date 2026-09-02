import React, { useState } from 'react';
import { SingleRowList } from '../components/SingleRow/SingleRowList';
import { SingleRowCard } from '../components/SingleRow/SingleRowCard';
import { StatusBadge } from '../components/UI/StatusBadge';
import { EvidenceDrawerModal } from '../components/UI/EvidenceDrawerModal';
import { MOCK_USERS } from '../sampleData/mockDatabase';

export const UsersPage = () => {
  const [inspectData, setInspectData] = useState(null);

  return (
    <div className="space-y-6">
      <div>
        <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">User Administration</span>
        <h2 className="text-2xl font-bold text-slate-100">Analyst Accounts & Access Control</h2>
        <p className="text-xs md:text-sm text-slate-400 mt-1 font-mono-code">
          Single-Row User Management Cards with Role Assignment & Multi-Factor Auth Gauges.
        </p>
      </div>

      <SingleRowList emptyTitle="No users configured">
        {MOCK_USERS.map((usr) => (
          <SingleRowCard
            key={usr.id}
            icon="ri-user-3-line"
            iconBg="bg-purple-500/10 text-purple-400 border-purple-500/20"
            title={`${usr.username} (${usr.email})`}
            subtitle={`Role: ${usr.role} &bull; Last Sign In: ${usr.last_login}`}
            tags={[usr.mfa_enabled ? 'MFA Hardware Key' : 'Standard Password']}
            statusBadge={<StatusBadge tone="online">{usr.status}</StatusBadge>}
            metrics={[]}
            actions={[
              {
                label: 'Edit Permissions',
                icon: 'ri-edit-line',
                variant: 'cyan',
                onClick: () => setInspectData(usr)
              },
              {
                label: 'Reset Password',
                icon: 'ri-key-line',
                variant: 'warning',
                onClick: () => alert(`Triggered password reset link for ${usr.username}`)
              }
            ]}
            expandableContent={
              <div className="text-xs space-y-1 font-mono-code text-slate-300">
                <p><strong className="text-cyan-400">User Identity ID:</strong> {usr.id}</p>
                <p><strong className="text-slate-400">Role Permissions:</strong> {usr.role}</p>
              </div>
            }
          />
        ))}
      </SingleRowList>

      <EvidenceDrawerModal
        isOpen={Boolean(inspectData)}
        onClose={() => setInspectData(null)}
        title={`User Account: ${inspectData?.username}`}
        data={inspectData}
      />
    </div>
  );
};

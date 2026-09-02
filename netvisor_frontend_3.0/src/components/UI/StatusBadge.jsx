import React from 'react';

export const StatusBadge = ({ children, tone = 'info' }) => {
  const styles = {
    critical: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    danger: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    high: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    warning: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    low: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
    success: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    online: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    info: 'bg-slate-800 text-slate-300 border-slate-700'
  };

  const key = String(tone).toLowerCase();
  const activeStyle = styles[key] || styles.info;

  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium border uppercase tracking-wider ${activeStyle}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      {children}
    </span>
  );
};

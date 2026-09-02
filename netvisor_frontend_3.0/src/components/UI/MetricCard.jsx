import React from 'react';

export const MetricCard = ({ title, value, meta, icon, accentColor = 'from-cyan-500/20 to-blue-600/10' }) => {
  return (
    <div className="glass-panel glass-panel-hover rounded-2xl p-5 relative overflow-hidden group">
      <div className={`absolute -right-6 -bottom-6 w-24 h-24 rounded-full bg-gradient-to-br ${accentColor} blur-xl group-hover:scale-125 transition-transform duration-300 pointer-events-none`}></div>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono-code">{title}</span>
        {icon && (
          <div className="w-9 h-9 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-cyan-400 text-lg">
            <i className={icon}></i>
          </div>
        )}
      </div>
      <div className="mt-3">
        <div className="text-2xl md:text-3xl font-bold text-slate-100 font-mono-code">{value}</div>
        {meta && <p className="text-xs text-slate-400 mt-1 font-mono-code truncate">{meta}</p>}
      </div>
    </div>
  );
};

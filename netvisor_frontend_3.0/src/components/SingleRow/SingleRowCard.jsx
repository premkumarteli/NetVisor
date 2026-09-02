import React, { useState } from 'react';

export const SingleRowCard = ({
  icon,
  iconBg = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  title,
  subtitle,
  tags = [],
  metrics = [],
  statusBadge,
  actions = [],
  expandableContent,
  onClick,
  className = ''
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const handleRowClick = (e) => {
    // If click is directly on an action button, don't trigger row toggle
    if (e.target.closest('button') || e.target.closest('a')) {
      return;
    }
    if (expandableContent) {
      setIsExpanded(!isExpanded);
    }
    if (onClick) {
      onClick(e);
    }
  };

  return (
    <div className={`glass-panel rounded-xl transition-all duration-200 hover:border-cyan-500/30 overflow-hidden ${className}`}>
      {/* Primary Horizontal Single-Row */}
      <div 
        onClick={handleRowClick}
        className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer select-none group"
      >
        {/* Left Zone: Identity & Icon */}
        <div className="flex items-center gap-3.5 min-w-0 flex-1">
          {icon && (
            <div className={`w-10 h-10 rounded-lg border flex items-center justify-center text-lg shrink-0 ${iconBg}`}>
              {typeof icon === 'string' ? <i className={icon}></i> : icon}
            </div>
          )}
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h4 className="font-semibold text-slate-100 text-sm md:text-base group-hover:text-cyan-300 transition-colors truncate">
                {title}
              </h4>
              {statusBadge}
              {tags.map((tag, idx) => (
                <span 
                  key={idx} 
                  className="px-2 py-0.5 text-[11px] font-mono-code rounded-md bg-slate-800/80 text-slate-400 border border-slate-700/60"
                >
                  {tag}
                </span>
              ))}
            </div>
            {subtitle && (
              <p className="text-xs text-slate-400 mt-0.5 truncate font-mono-code">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        {/* Center Zone: Inline Telemetry & Metrics */}
        {metrics.length > 0 && (
          <div className="flex items-center gap-4 shrink-0 px-2 py-1 bg-slate-900/60 rounded-lg border border-slate-800/80">
            {metrics.map((metric, idx) => (
              <div key={idx} className="flex flex-col text-right">
                <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
                  {metric.label}
                </span>
                <span className={`text-xs font-mono-code font-medium ${metric.color || 'text-slate-200'}`}>
                  {metric.value}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Right Zone: Single-Row Actions ("Single Row Functions") */}
        <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
          {actions.map((act, idx) => (
            <button
              key={idx}
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                if (act.onClick) act.onClick(e);
              }}
              title={act.label}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg flex items-center gap-1.5 transition-all duration-150 border shadow-sm ${
                act.variant === 'danger'
                  ? 'bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20'
                  : act.variant === 'warning'
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
                  : act.variant === 'success'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                  : 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30 hover:bg-cyan-500/20'
              }`}
            >
              {act.icon && typeof act.icon === 'string' ? <i className={act.icon}></i> : act.icon}
              <span>{act.label}</span>
            </button>
          ))}

          {expandableContent && (
            <div className="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-cyan-400 hover:bg-slate-800/80 transition-colors">
              <i className={`ri-arrow-down-s-line transition-transform duration-200 ${isExpanded ? 'rotate-180 text-cyan-400' : ''}`}></i>
            </div>
          )}
        </div>
      </div>

      {/* Expandable Accordion Content Drawer */}
      {expandableContent && isExpanded && (
        <div className="px-4 pb-4 pt-2 border-t border-slate-800/80 bg-slate-950/60">
          {expandableContent}
        </div>
      )}
    </div>
  );
};

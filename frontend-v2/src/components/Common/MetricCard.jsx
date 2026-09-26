import React from 'react';

export const MetricCard = ({
  icon,
  label,
  value,
  meta,
  accent = 'var(--blue)',
  onClick,
  className = '',
}) => {
  return (
    <div
      onClick={onClick}
      className={`glass-card p-5 transition-all duration-200 relative overflow-hidden ${
        onClick ? 'cursor-pointer hover:border-white/20 hover:translate-y-[-1px]' : ''
      } ${className}`}
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-[#9AA3B8]">
          {label}
        </span>
        <div
          className="w-7 h-7 rounded-[8px] flex items-center justify-center shrink-0"
          style={{
            backgroundColor: `${accent}1F`, // ~12% opacity
            color: accent,
          }}
        >
          {typeof icon === 'string' ? (
            <i className={`${icon} text-sm`}></i>
          ) : (
            icon
          )}
        </div>
      </div>

      <div className="text-3xl font-extrabold tabular-nums tracking-[-0.02em] text-[#F1F3F9] mb-1.5">
        {value}
      </div>

      {meta && (
        <div className="text-xs text-[#5E6579] font-medium truncate">
          {meta}
        </div>
      )}
    </div>
  );
};

export default MetricCard;

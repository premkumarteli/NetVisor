import React from 'react';

// Generates smooth SVG sparkline path
const Sparkline = ({ color = '#3B82F6', id = 'spark' }) => {
  return (
    <svg className="w-full h-5 overflow-visible" viewBox="0 0 100 20" fill="none" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${id}`} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path
        d="M 0,14 Q 18,18 35,9 T 70,11 T 100,4"
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinecap="round"
        className="transition-all duration-300"
      />
      <path
        d="M 0,14 Q 18,18 35,9 T 70,11 T 100,4 L 100,20 L 0,20 Z"
        fill={`url(#grad-${id})`}
      />
    </svg>
  );
};

export const MetricCard = ({
  icon,
  label,
  value,
  meta,
  badgeText,
  badgeTone = 'success',
  accent = '#3B82F6',
  sparkColor = '#3B82F6',
  onClick,
  className = '',
}) => {
  return (
    <div
      onClick={onClick}
      className={`glass-card p-4 relative overflow-hidden flex flex-col justify-between group cursor-pointer transition-all duration-300 ${className}`}
      style={{
        '--card-accent': accent,
      }}
    >
      {/* Dynamic Ambient Hover Glow behind the card */}
      <div
        className="absolute -top-12 -right-12 w-28 h-28 rounded-full blur-2xl opacity-0 group-hover:opacity-40 transition-opacity duration-500 pointer-events-none"
        style={{ backgroundColor: accent }}
      />

      <div className="flex items-start gap-3 mb-1.5 relative z-10">
        {/* Left Square Icon Container with Animated Glow on Hover */}
        <div
          className="w-8.5 h-8.5 rounded-xl flex items-center justify-center shrink-0 border transition-all duration-300 group-hover:scale-105 group-hover:shadow-[0_0_16px_var(--card-accent)]"
          style={{
            backgroundColor: `${accent}18`,
            borderColor: `${accent}35`,
            color: accent,
          }}
        >
          {typeof icon === 'string' ? (
            <i className={`${icon} text-base transition-transform duration-300 group-hover:rotate-6`}></i>
          ) : (
            icon
          )}
        </div>

        {/* Metric Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-1.5">
            <span className="text-xs font-medium text-[#9AA3B8] group-hover:text-white transition-colors truncate">
              {label}
            </span>
            {badgeText && (
              <span
                className={`text-[9.5px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1 transition-transform group-hover:scale-105 ${
                  badgeTone === 'danger'
                    ? 'bg-rose-500/15 text-[#FB7185] border border-rose-500/30 shadow-[0_0_8px_rgba(251,113,133,0.25)]'
                    : badgeTone === 'warning'
                    ? 'bg-amber-500/15 text-[#F59E0B] border border-amber-500/30 shadow-[0_0_8px_rgba(245,158,11,0.25)]'
                    : 'bg-emerald-500/15 text-[#34D399] border border-emerald-500/30 shadow-[0_0_8px_rgba(52,211,153,0.25)]'
                }`}
              >
                {badgeText}
              </span>
            )}
          </div>

          <div className="text-2xl font-black tabular-nums tracking-tight text-[#FFFFFF] mt-0.5 group-hover:text-blue-100 transition-colors">
            {value}
          </div>
        </div>
      </div>

      {/* Sparkline Wave at bottom */}
      <div className="mt-1 opacity-85 group-hover:opacity-100 transition-opacity relative z-10">
        <Sparkline color={sparkColor} id={label.replace(/\s+/g, '-')} />
      </div>

      {meta && (
        <div className="text-[10.5px] text-[#5E6579] font-medium truncate mt-0.5 relative z-10">
          {meta}
        </div>
      )}
    </div>
  );
};

export default MetricCard;

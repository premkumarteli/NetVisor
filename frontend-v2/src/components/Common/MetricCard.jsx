import React from 'react';

// Generates smooth SVG sparkline path
const Sparkline = ({ color = '#3B82F6', id = 'spark' }) => {
  return (
    <svg className="w-full h-9 overflow-visible" viewBox="0 0 100 24" fill="none" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${id}`} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path
        d="M 0,16 Q 18,22 35,12 T 70,14 T 100,6"
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <path
        d="M 0,16 Q 18,22 35,12 T 70,14 T 100,6 L 100,24 L 0,24 Z"
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
      className={`glass-card p-5 transition-all duration-200 relative overflow-hidden flex flex-col justify-between ${
        onClick ? 'cursor-pointer hover:border-white/15 hover:translate-y-[-1px]' : ''
      } ${className}`}
      style={{
        background: 'rgba(10, 14, 26, 0.72)',
        backdropFilter: 'blur(20px) saturate(150%)',
        WebkitBackdropFilter: 'blur(20px) saturate(150%)',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
      }}
    >
      <div className="flex items-start gap-3.5 mb-2">
        {/* Left Square Icon Container */}
        <div
          className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border"
          style={{
            backgroundColor: `${accent}1A`,
            borderColor: `${accent}33`,
            color: accent,
          }}
        >
          {typeof icon === 'string' ? (
            <i className={`${icon} text-lg`}></i>
          ) : (
            icon
          )}
        </div>

        {/* Metric Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-[#9AA3B8] truncate">
              {label}
            </span>
            {badgeText && (
              <span
                className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full flex items-center gap-1 ${
                  badgeTone === 'danger'
                    ? 'bg-rose-500/15 text-[#FB7185] border border-rose-500/20'
                    : badgeTone === 'warning'
                    ? 'bg-amber-500/15 text-[#F59E0B] border border-amber-500/20'
                    : 'bg-emerald-500/15 text-[#34D399] border border-emerald-500/20'
                }`}
              >
                {badgeText}
              </span>
            )}
          </div>

          <div className="text-2xl font-extrabold tabular-nums tracking-[-0.02em] text-[#FFFFFF] mt-0.5">
            {value}
          </div>
        </div>
      </div>

      {/* Sparkline Wave at bottom */}
      <div className="mt-1 pt-1 opacity-80">
        <Sparkline color={sparkColor} id={label.replace(/\s+/g, '-')} />
      </div>

      {meta && (
        <div className="text-[11px] text-[#5E6579] font-medium truncate mt-1">
          {meta}
        </div>
      )}
    </div>
  );
};

export default MetricCard;

import React from 'react';

// Generates smooth SVG sparkline path
const Sparkline = ({ color = '#3B82F6', id = 'spark' }) => {
  return (
    <svg className="w-full h-5 overflow-visible" viewBox="0 0 100 20" fill="none" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${id}`} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path
        d="M 0,14 Q 18,18 35,9 T 70,11 T 100,4"
        fill="none"
        stroke={color}
        strokeWidth="1.6"
        strokeLinecap="round"
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
      className={`glass-card p-3.5 relative overflow-hidden flex flex-col justify-between ${
        onClick ? 'cursor-pointer hover:border-white/20 hover:translate-y-[-1px]' : ''
      } ${className}`}
    >
      <div className="flex items-start gap-2.5 mb-1">
        {/* Left Square Icon Container */}
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border"
          style={{
            backgroundColor: `${accent}18`,
            borderColor: `${accent}30`,
            color: accent,
          }}
        >
          {typeof icon === 'string' ? (
            <i className={`${icon} text-base`}></i>
          ) : (
            icon
          )}
        </div>

        {/* Metric Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-1.5">
            <span className="text-[11px] font-medium text-[#9AA3B8] truncate">
              {label}
            </span>
            {badgeText && (
              <span
                className={`text-[9.5px] font-bold px-1.5 py-0.2 rounded-full flex items-center gap-0.5 ${
                  badgeTone === 'danger'
                    ? 'bg-rose-500/15 text-[#FB7185] border border-rose-500/25'
                    : badgeTone === 'warning'
                    ? 'bg-amber-500/15 text-[#F59E0B] border border-amber-500/25'
                    : 'bg-emerald-500/15 text-[#34D399] border border-emerald-500/25'
                }`}
              >
                {badgeText}
              </span>
            )}
          </div>

          <div className="text-xl font-extrabold tabular-nums tracking-tight text-[#FFFFFF] mt-0.5">
            {value}
          </div>
        </div>
      </div>

      {/* Sparkline Wave at bottom */}
      <div className="mt-0.5 opacity-85">
        <Sparkline color={sparkColor} id={label.replace(/\s+/g, '-')} />
      </div>

      {meta && (
        <div className="text-[10px] text-[#5E6579] font-medium truncate mt-0.5">
          {meta}
        </div>
      )}
    </div>
  );
};

export default MetricCard;

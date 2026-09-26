import React from 'react';

const TONE_MAP = {
  blue: { bg: 'rgba(96, 165, 250, 0.15)', text: '#60A5FA', border: 'rgba(96, 165, 250, 0.25)' },
  rose: { bg: 'rgba(251, 113, 133, 0.15)', text: '#FB7185', border: 'rgba(251, 113, 133, 0.25)' },
  danger: { bg: 'rgba(251, 113, 133, 0.15)', text: '#FB7185', border: 'rgba(251, 113, 133, 0.25)' },
  critical: { bg: 'rgba(251, 113, 133, 0.15)', text: '#FB7185', border: 'rgba(251, 113, 133, 0.25)' },
  amber: { bg: 'rgba(245, 158, 11, 0.15)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.25)' },
  warning: { bg: 'rgba(245, 158, 11, 0.15)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.25)' },
  medium: { bg: 'rgba(245, 158, 11, 0.15)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.25)' },
  teal: { bg: 'rgba(84, 200, 232, 0.15)', text: '#54C8E8', border: 'rgba(84, 200, 232, 0.25)' },
  green: { bg: 'rgba(52, 211, 153, 0.15)', text: '#34D399', border: 'rgba(52, 211, 153, 0.25)' },
  success: { bg: 'rgba(52, 211, 153, 0.15)', text: '#34D399', border: 'rgba(52, 211, 153, 0.25)' },
  low: { bg: 'rgba(52, 211, 153, 0.15)', text: '#34D399', border: 'rgba(52, 211, 153, 0.25)' },
  violet: { bg: 'rgba(167, 139, 250, 0.15)', text: '#A78BFA', border: 'rgba(167, 139, 250, 0.25)' },
  neutral: { bg: 'rgba(154, 163, 184, 0.12)', text: '#9AA3B8', border: 'rgba(154, 163, 184, 0.2)' },
};

export const StatusBadge = ({ tone = 'neutral', icon, children, className = '' }) => {
  const normalizedTone = String(tone).toLowerCase();
  const config = TONE_MAP[normalizedTone] || TONE_MAP.neutral;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider text-[10.5px] border ${className}`}
      style={{
        backgroundColor: config.bg,
        color: config.text,
        borderColor: config.border,
      }}
    >
      {icon && <i className={icon} style={{ fontSize: '11px' }}></i>}
      {children}
    </span>
  );
};

export default StatusBadge;

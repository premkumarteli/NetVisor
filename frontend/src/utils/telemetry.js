export const confidenceTone = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 'neutral';
  if (numeric >= 0.85) return 'success';
  if (numeric >= 0.55) return 'warning';
  return 'danger';
};

export const formatConfidence = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 'unknown';
  return `${Math.round(Math.max(0, Math.min(numeric, 1)) * 100)}%`;
};

export const directionTone = (value) => {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'outbound' || normalized === 'egress') return 'accent';
  if (normalized === 'inbound' || normalized === 'ingress') return 'warning';
  if (normalized === 'lateral' || normalized === 'internal') return 'success';
  if (normalized === 'external') return 'danger';
  return 'neutral';
};

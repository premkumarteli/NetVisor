export const formatCompact = (value) => {
  const numeric = Number(value) || 0;
  return new Intl.NumberFormat('en', {
    notation: numeric >= 10000 ? 'compact' : 'standard',
    maximumFractionDigits: numeric >= 10000 ? 1 : 0,
  }).format(numeric).toUpperCase();
};

export const resolveSeverityCount = (distribution = {}, severity) => {
  const normalized = String(severity).toUpperCase();
  return Number(distribution[normalized] ?? distribution[normalized.toLowerCase()] ?? 0);
};

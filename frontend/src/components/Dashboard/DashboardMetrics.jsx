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

export const SceneMetricCard = ({ icon, label, value, meta, tone = 'accent', signal }) => {
  const isThreatAlert = label?.toLowerCase().includes('threat') && (
    typeof value === 'number' ? value > 0 : parseInt(value, 10) > 0
  );

  return (
    <article className={`cinematic-metric cinematic-metric--${tone} ${isThreatAlert ? 'is-threat-pulsing' : ''}`.trim()}>
      <div className="cinematic-metric__art" aria-hidden="true">
        <span></span>
        <span></span>
        <span></span>
      </div>
      <div className="cinematic-metric__header">
        <span className="cinematic-metric__icon"><i className={icon}></i></span>
        <span>{label}</span>
      </div>
      <strong>{value}</strong>
      <p>{meta}</p>
      {signal ? <small>{signal}</small> : null}
    </article>
  );
};

export const SeverityCard = ({ severity, count }) => (
  <div className={`cinematic-severity cinematic-severity--${severity.toLowerCase()}`}>
    <span>{severity}</span>
    <strong>{count}</strong>
    <small>{count === 1 ? 'open signal' : 'open signals'}</small>
  </div>
);

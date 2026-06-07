const MetricCard = ({
  icon,
  label,
  value,
  meta,
  accent,
  progress = null,
  className = '',
}) => (
  <article
    className={`nv-metric animate-reveal ${className}`.trim()}
    style={accent ? { '--nv-accent': accent } : undefined}
  >
    <div className="nv-metric__header">
      {icon ? (
        <span className="nv-metric__icon">
          <i className={icon}></i>
        </span>
      ) : null}
      <span className="nv-metric__label">{label}</span>
    </div>
    <div className="nv-metric__value">{value}</div>
    {progress !== null ? (
      <div className="nv-metric__progress-container">
        <div className="nv-metric__progress-bar">
          <div className="nv-metric__progress-fill" style={{ width: `${Math.min(Math.max(progress, 0), 100)}%` }} />
        </div>
      </div>
    ) : null}
    {meta ? <div className="nv-metric__meta">{meta}</div> : null}
  </article>
);

export default MetricCard;

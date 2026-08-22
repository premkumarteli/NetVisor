import { formatUtcTimestampToLocal } from '../../utils/time';
import { translateThreat, formatRelativeTime } from '../../utils/intelTranslator';

export const ThreatFeedItem = ({ alert, onClick }) => {
  const intel = translateThreat(alert);
  const severity = intel.severity;
  const localTime = formatUtcTimestampToLocal(alert.timestamp);
  const relativeTime = formatRelativeTime(alert.timestamp);

  return (
    <button type="button" className={`cinematic-threat cinematic-threat--${severity.toLowerCase()}`} onClick={onClick}>
      <span className="cinematic-threat__icon"><i className="ri-alarm-warning-line"></i></span>
      <span className="cinematic-threat__copy">
        <strong>{intel.title}</strong>
        <span>{intel.targetAsset} &bull; {intel.summary}</span>
        <em>{severity} · {intel.riskScore}%</em>
      </span>
      <span className="cinematic-threat__time" title={localTime}>{relativeTime}</span>
    </button>
  );
};

export const SystemStatusRow = ({ icon, label, value, tone = 'success' }) => (
  <div className="cinematic-status-row">
    <span><i className={icon}></i>{label}</span>
    <strong className={`cinematic-status-row__value cinematic-status-row__value--${tone}`}>{value}</strong>
  </div>
);

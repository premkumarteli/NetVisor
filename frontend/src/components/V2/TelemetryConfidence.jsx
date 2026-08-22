import StatusBadge from './StatusBadge';
import { directionTone } from '../../utils/telemetry';
import { translateTelemetrySource } from '../../utils/intelTranslator';

const TelemetryConfidence = ({
  source,
  confidence,
  direction,
  scope,
  compact = false,
}) => {
  const telemetry = translateTelemetrySource(source, confidence);

  return (
    <div className={`nv-truth-stack ${compact ? 'nv-truth-stack--compact' : ''}`.trim()}>
      {source || confidence !== undefined ? (
        <StatusBadge tone={telemetry.badgeTone} icon="ri-fingerprint-line">
          {telemetry.label} {telemetry.confidencePercent ? `· ${telemetry.confidencePercent}` : ''}
        </StatusBadge>
      ) : null}
      {direction && direction !== 'unknown' ? (
        <StatusBadge tone={directionTone(direction)} icon="ri-route-line">
          {String(direction).replace(/_/g, ' ').toUpperCase()}
        </StatusBadge>
      ) : null}
      {scope && scope !== 'unknown' ? (
        <span className="nv-truth-stack__meta">{String(scope).replace(/_/g, ' ')}</span>
      ) : null}
    </div>
  );
};

export default TelemetryConfidence;

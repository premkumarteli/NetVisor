import StatusBadge from './StatusBadge';
import { confidenceTone, directionTone, formatConfidence } from '../../utils/telemetry';

const normalizeSource = (value) => String(value || 'unknown').replace(/_/g, ' ');

const TelemetryConfidence = ({
  source,
  confidence,
  direction,
  scope,
  compact = false,
}) => (
  <div className={`nv-truth-stack ${compact ? 'nv-truth-stack--compact' : ''}`.trim()}>
    {source || confidence !== undefined ? (
      <StatusBadge tone={confidenceTone(confidence)} icon="ri-fingerprint-line">
        {normalizeSource(source)} {confidence !== undefined ? formatConfidence(confidence) : ''}
      </StatusBadge>
    ) : null}
    {direction ? (
      <StatusBadge tone={directionTone(direction)} icon="ri-route-line">
        {String(direction).replace(/_/g, ' ')}
      </StatusBadge>
    ) : null}
    {scope ? (
      <span className="nv-truth-stack__meta">{String(scope).replace(/_/g, ' ')}</span>
    ) : null}
  </div>
);

export default TelemetryConfidence;

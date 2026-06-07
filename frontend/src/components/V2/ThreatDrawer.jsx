import SidePanel from './SidePanel';
import StatusBadge from './StatusBadge';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { getRiskTone } from '../../utils/presentation';

const DetailRow = ({ label, value }) => (
  <div className="nv-summary-tile">
    <span>{label}</span>
    <strong>{value}</strong>
  </div>
);

const ThreatDrawer = ({ open, threat, onClose, title = "Threat Audit Details" }) => {
  if (!open || !threat) return null;

  const timestamp = formatUtcTimestampToLocal(threat.timestamp || threat.last_seen);
  const severity = threat.severity || 'HIGH';
  const targetIp = threat.device_ip || threat.src_ip || 'Unknown';
  const detectionName = threat.message || threat.breakdown?.primary_detection || 'Anomaly Detected';
  const vpnProvider = threat.breakdown?.vpn_provider || null;
  const flowId = threat.flow_id ? String(threat.flow_id).slice(0, 12) : null;

  return (
    <SidePanel
      open={open}
      title={title}
      description="Inspect security telemetry, anomaly confidence, and detection context."
      onClose={onClose}
    >
      <div className="nv-evidence-grid">
        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <DetailRow label="Severity" value={<StatusBadge tone={getRiskTone(severity)}>{severity}</StatusBadge>} />
          <DetailRow label="Timestamp" value={<span className="mono">{timestamp}</span>} />
          <DetailRow label="Target Host/IP" value={<span className="mono">{targetIp}</span>} />
          <DetailRow label="Risk Score" value={threat.risk_score ? `${Math.round(threat.risk_score)}%` : '-'} />
        </div>

        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <DetailRow label="Detection Engine" value={threat.breakdown?.primary_detection || 'AI Anomaly Classifier'} />
          {vpnProvider ? <DetailRow label="VPN Provider" value={vpnProvider} /> : null}
          {flowId ? <DetailRow label="Flow ID" value={<span className="mono">{flowId}</span>} /> : null}
          <DetailRow label="Application" value={threat.application || threat.domain || 'Direct Socket Connection'} />
        </div>

        {threat.breakdown?.reasons && threat.breakdown.reasons.length > 0 ? (
          <div>
            <div className="nv-section__caption">Detection Signals</div>
            <div className="nv-inline-actions" style={{ gap: '0.5rem', marginTop: '0.45rem' }}>
              {threat.breakdown.reasons.map((reason, idx) => (
                <StatusBadge key={idx} tone="neutral">{reason}</StatusBadge>
              ))}
            </div>
          </div>
        ) : null}

        <div>
          <div className="nv-section__caption" style={{ marginBottom: '0.5rem' }}>Audit Log Reason</div>
          <p className="nv-auth__description" style={{ padding: '0.75rem', borderRadius: '12px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--nv-border)' }}>
            {detectionName}
          </p>
        </div>

        <div>
          <div className="nv-section__caption">Raw Event Telemetry</div>
          <pre className="nv-code-block">{JSON.stringify(threat, null, 2)}</pre>
        </div>
      </div>
    </SidePanel>
  );
};

export default ThreatDrawer;

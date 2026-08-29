import SidePanel from './SidePanel';
import StatusBadge from './StatusBadge';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { getRiskTone } from '../../utils/presentation';
import { translateThreat, formatRelativeTime } from '../../utils/intelTranslator';

const DetailRow = ({ label, value }) => (
  <div className="nv-summary-tile">
    <span>{label}</span>
    <strong>{value}</strong>
  </div>
);

const ThreatDrawer = ({ open, threat, onClose, title = 'Threat Audit Details' }) => {
  if (!open || !threat) return null;

  const intel = translateThreat(threat);
  const localTime = formatUtcTimestampToLocal(threat.timestamp || threat.last_seen);
  const relativeTime = formatRelativeTime(threat.timestamp || threat.last_seen);
  const severity = intel.severity;
  const flowId = threat.flow_id ? String(threat.flow_id).slice(0, 12) : null;

  return (
    <SidePanel
      open={open}
      title={intel.title || title}
      description="Operational incident briefing, threat classification, and analyst actions."
      onClose={onClose}
    >
      <div className="nv-evidence-grid">
        {/* Human Incident Narrative Banner */}
        <div style={{
          padding: '1.1rem',
          borderRadius: '16px',
          background: severity === 'CRITICAL'
            ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.12), rgba(239, 68, 68, 0.04))'
            : 'linear-gradient(135deg, rgba(245, 158, 11, 0.12), rgba(245, 158, 11, 0.04))',
          border: `1px solid ${severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.45rem' }}>
            <i className="ri-shield-flash-line" style={{ color: severity === 'CRITICAL' ? '#f87171' : '#fbbf24', fontSize: '1.1rem' }}></i>
            <strong style={{ fontSize: '0.95rem', color: '#fff' }}>Incident Summary</strong>
            <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--nv-text-muted)' }}>{relativeTime}</span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--nv-text-soft)', lineHeight: '1.45', margin: 0 }}>
            {intel.summary}
          </p>
        </div>

        {/* Actionable Recommendations */}
        <div style={{
          padding: '1rem',
          borderRadius: '14px',
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid var(--nv-border)',
        }}>
          <div className="nv-section__caption" style={{ marginBottom: '0.4rem', color: 'var(--nv-accent)' }}>
            <i className="ri-checkbox-circle-line" style={{ marginRight: '0.35rem' }}></i> Recommended Analyst Action
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--nv-text)', margin: '0 0 0.5rem 0', lineHeight: 1.4 }}>
            {intel.recommendation}
          </p>
          <div style={{ fontSize: '0.78rem', color: 'var(--nv-text-muted)', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '0.4rem' }}>
            <strong>Potential Impact:</strong> {intel.impact}
          </div>
        </div>

        {/* Structured Context Tiles */}
        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <DetailRow label="Severity" value={<StatusBadge tone={getRiskTone(severity)}>{severity}</StatusBadge>} />
          <DetailRow label="Threat Score" value={<span style={{ color: intel.riskScore > 75 ? '#f87171' : '#fbbf24' }}>{intel.riskScore}% Anomaly</span>} />
          <DetailRow label="Detected Asset" value={<span className="mono">{intel.targetAsset}</span>} />
          <DetailRow label="Time (Local)" value={<span className="mono" title={threat.timestamp}>{localTime}</span>} />
        </div>

        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <DetailRow label="Destination" value={<span className="mono">{intel.destination}</span>} />
          <DetailRow label="Application" value={threat.application || threat.domain || 'Direct Socket Connection'} />
          {intel.vpnProvider ? <DetailRow label="VPN Tunnel" value={intel.vpnProvider} /> : null}
          {flowId ? <DetailRow label="Flow ID" value={<span className="mono">{flowId}</span>} /> : null}
        </div>

        {/* Detection Trigger Details */}
        <div>
          <div className="nv-section__caption" style={{ marginBottom: '0.35rem' }}>Trigger Details</div>
          <div style={{ padding: '0.75rem', borderRadius: '12px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--nv-border)' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--nv-text-muted)', display: 'block' }}>Engine Rule ID</span>
            <code style={{ color: 'var(--nv-accent)', fontSize: '0.82rem' }}>{intel.rawKey}</code>
          </div>
        </div>

        {/* Advanced Raw JSON (Collapsible) */}
        <details style={{ marginTop: '0.5rem', cursor: 'pointer' }}>
          <summary style={{ fontSize: '0.78rem', color: 'var(--nv-text-muted)', userSelect: 'none', padding: '0.4rem 0' }}>
            <i className="ri-code-s-slash-line" style={{ marginRight: '0.3rem' }}></i> View Raw Event JSON Payload
          </summary>
          <pre className="nv-code-block" style={{ marginTop: '0.5rem', maxHeight: '180px', overflowY: 'auto' }}>
            {JSON.stringify(threat, null, 2)}
          </pre>
        </details>
      </div>
    </SidePanel>
  );
};

export default ThreatDrawer;

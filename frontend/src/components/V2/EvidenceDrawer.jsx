import SidePanel from './SidePanel';
import StatusBadge from './StatusBadge';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { formatByteCount, getRiskTone } from '../../utils/presentation';
import { translateDestination, formatRelativeTime } from '../../utils/intelTranslator';

const EvidenceRow = ({ label, value }) => (
  <div className="nv-summary-tile">
    <span>{label}</span>
    <strong>{value}</strong>
  </div>
);

const EvidenceDrawer = ({ open, event, onClose, footer }) => {
  if (!open || !event) {
    return null;
  }

  const destInfo = translateDestination(
    event.dst_ip,
    event.domain || event.host,
    event.dst_port || event.port,
    event.protocol,
    event.application
  );

  const localTime = formatUtcTimestampToLocal(event.timestamp || event.last_seen || event.time);
  const relativeTime = formatRelativeTime(event.timestamp || event.last_seen || event.time);
  const bytes = formatByteCount(event.byte_count || event.size || 0);
  const severity = event.severity || 'LOW';
  const srcIp = event.src_ip || 'Internal Asset';
  const dstIp = event.dst_ip || '-';

  return (
    <SidePanel
      open={open}
      title={destInfo.primary}
      description={`Session observed ${relativeTime} between ${srcIp} and ${destInfo.primary}.`}
      onClose={onClose}
      footer={footer}
    >
      <div className="nv-evidence-grid">
        {/* Connection Flow Visual */}
        <div style={{
          padding: '1rem',
          borderRadius: '16px',
          background: 'linear-gradient(135deg, rgba(84, 200, 232, 0.08), rgba(255, 255, 255, 0.02))',
          border: '1px solid rgba(84, 200, 232, 0.2)',
        }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--nv-accent)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, display: 'block', marginBottom: '0.6rem' }}>
            Connection Flow Path
          </span>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
            <div style={{ textAlign: 'left' }}>
              <strong style={{ fontSize: '0.9rem', color: '#fff', display: 'block' }}>{srcIp}</strong>
              <small style={{ color: 'var(--nv-text-muted)', fontSize: '0.75rem' }}>Source Host</small>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1, padding: '0 0.5rem' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--nv-accent)', marginBottom: '0.2rem' }}>
                {event.protocol || 'TCP'} {event.dst_port ? `:${event.dst_port}` : ''}
              </span>
              <div style={{ height: '2px', width: '100%', background: 'linear-gradient(90deg, transparent, var(--nv-accent), transparent)' }}></div>
              <span style={{ fontSize: '0.7rem', color: 'var(--nv-text-muted)', marginTop: '0.2rem' }}>{bytes}</span>
            </div>
            <div style={{ textAlign: 'right' }}>
              <strong style={{ fontSize: '0.9rem', color: '#fff', display: 'block' }}>{destInfo.primary}</strong>
              <small className="mono" style={{ color: 'var(--nv-text-muted)', fontSize: '0.75rem' }}>{dstIp}</small>
            </div>
          </div>
        </div>

        {/* Structured Context Tiles */}
        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <EvidenceRow label="Security Posture" value={<StatusBadge tone={getRiskTone(severity)}>{severity}</StatusBadge>} />
          <EvidenceRow label="Observed" value={<span>{relativeTime}</span>} />
          <EvidenceRow label="Identified App" value={event.application || destInfo.primary} />
          <EvidenceRow label="Transfer Size" value={<span className="mono">{bytes}</span>} />
        </div>

        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <EvidenceRow label="Destination Endpoint" value={<span className="mono">{destInfo.meta}</span>} />
          <EvidenceRow label="Exact Time (Local)" value={<span className="mono">{localTime}</span>} />
          <EvidenceRow label="Protocol" value={<span className="mono">{event.protocol || 'TCP/IP'}</span>} />
          <EvidenceRow label="Duration" value={<span className="mono">{event.duration ? `${event.duration}s` : 'Active / Streaming'}</span>} />
        </div>

        {/* Advanced Raw JSON (Collapsible) */}
        <details style={{ marginTop: '0.5rem', cursor: 'pointer' }}>
          <summary style={{ fontSize: '0.78rem', color: 'var(--nv-text-muted)', userSelect: 'none', padding: '0.4rem 0' }}>
            <i className="ri-code-s-slash-line" style={{ marginRight: '0.3rem' }}></i> View Raw Context JSON Payload
          </summary>
          <pre className="nv-code-block" style={{ marginTop: '0.5rem', maxHeight: '180px', overflowY: 'auto' }}>
            {JSON.stringify(event, null, 2)}
          </pre>
        </details>
      </div>
    </SidePanel>
  );
};

export default EvidenceDrawer;

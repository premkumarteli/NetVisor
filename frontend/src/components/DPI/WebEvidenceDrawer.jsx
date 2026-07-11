import SidePanel from '../V2/SidePanel';
import StatusBadge from '../V2/StatusBadge';
import SectionCard from '../V2/SectionCard';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { formatBrowserLabel, formatByteCount, getRiskTone } from '../../utils/presentation';
import {
  getWebEvidencePrimaryLabel,
  getWebEvidenceSearchQueries,
  getWebEvidenceTitles,
  getWebEvidenceUrls,
  normalizeWebRiskLevel,
} from '../../utils/webEvidence';

const formatConfidence = (value) => {
  const score = Number(value) || 0;
  if (score >= 0.8) {
    return `High (${score.toFixed(2)})`;
  }
  if (score >= 0.55) {
    return `Medium (${score.toFixed(2)})`;
  }
  return `Low (${score.toFixed(2)})`;
};

const WebEvidenceDrawer = ({ open, item, onClose, footer }) => {
  if (!open) {
    return null;
  }

  const urls = getWebEvidenceUrls(item);
  const titles = getWebEvidenceTitles(item);
  const queries = getWebEvidenceSearchQueries(item);
  const requestBytes = Number(item?.request_bytes) || 0;
  const responseBytes = Number(item?.response_bytes) || 0;
  const eventCount = Number(item?.event_count) || 1;
  const riskLevel = normalizeWebRiskLevel(item?.risk_level);
  const title = item?.group_label || getWebEvidencePrimaryLabel(item);

  // YouTube detection
  const isYouTube =
    String(item?.domain || item?.base_domain || '').toLowerCase().includes('youtube.com') ||
    urls.some((u) => String(u).toLowerCase().includes('youtube.com') || String(u).toLowerCase().includes('youtu.be'));

  const youtubeVideos = [];
  if (isYouTube) {
    urls.forEach((url, index) => {
      const isYt = String(url).toLowerCase().includes('youtube.com') || String(url).toLowerCase().includes('youtu.be');
      if (isYt) {
        let videoTitle = titles[index] || titles[0] || item?.page_title || item?.group_label || 'YouTube Inspected Video';
        if (videoTitle.toLowerCase() === 'youtube' || videoTitle.toLowerCase() === 'youtube.com') {
          videoTitle = 'YouTube Inspected Video';
        }
        youtubeVideos.push({ url, title: videoTitle });
      }
    });

    if (youtubeVideos.length === 0) {
      youtubeVideos.push({
        url: item?.page_url || item?.url || 'https://youtube.com',
        title: item?.page_title || item?.group_label || 'YouTube Streaming Session',
      });
    }
  }

  return (
    <SidePanel
      open={open}
      title={title}
      description="Redacted evidence only. The backend stores metadata and sanitized snippets, not full payload bodies."
      onClose={onClose}
      footer={footer ?? (
        <StatusBadge tone={getRiskTone(riskLevel)}>
          {riskLevel} · {formatConfidence(item?.confidence_score)}
        </StatusBadge>
      )}
    >
      <div className="nv-evidence-grid">
        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <div className="nv-summary-tile">
            <span>Device</span>
            <strong className="mono">{item?.device_ip || '-'}</strong>
            <p>{formatBrowserLabel(item?.browser_name, item?.process_name)}</p>
          </div>
          <div className="nv-summary-tile">
            <span>Seen</span>
            <strong>{formatUtcTimestampToLocal(item?.last_seen)}</strong>
            <p>{item?.first_seen ? `First seen ${formatUtcTimestampToLocal(item.first_seen)}` : 'No first-seen timestamp'}</p>
          </div>
          <div className="nv-summary-tile">
            <span>Scope</span>
            <strong>{eventCount} event{eventCount === 1 ? '' : 's'}</strong>
            <p>{urls.length} URL{urls.length === 1 ? '' : 's'} · {titles.length} title{titles.length === 1 ? '' : 's'}</p>
          </div>
          <div className="nv-summary-tile">
            <span>Traffic</span>
            <strong>{formatByteCount(requestBytes + responseBytes)}</strong>
            <p>{formatByteCount(requestBytes)} request · {formatByteCount(responseBytes)} response</p>
          </div>
        </div>

        {isYouTube && youtubeVideos.length > 0 && (
          <SectionCard title="YouTube Inspected Stream" caption="DPI Media Decoder" className="nv-section--clarity">
            <div className="nv-stack" style={{ gap: '0.75rem' }}>
              {youtubeVideos.map((vid, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  padding: '0.85rem 1rem',
                  backgroundColor: 'rgba(239, 68, 68, 0.05)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  borderRadius: '12px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: 0 }}>
                    <div style={{
                      backgroundColor: 'rgba(239, 68, 68, 0.15)',
                      color: '#ef4444',
                      width: '40px',
                      height: '40px',
                      borderRadius: '50%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '1.25rem',
                      flexShrink: 0,
                    }}>
                      <i className="ri-youtube-fill"></i>
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.7rem', color: '#ef4444', fontWeight: 600, textTransform: 'uppercase' }}>
                        Viewing on YouTube
                      </div>
                      <div style={{ fontSize: '0.9rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={vid.title}>
                        {vid.title}
                      </div>
                      <a
                        href={vid.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mono"
                        style={{ fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.2rem', marginTop: '0.15rem', wordBreak: 'break-all', color: '#ef4444' }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {vid.url}
                        <i className="ri-external-link-line" style={{ fontSize: '10px' }}></i>
                      </a>
                    </div>
                  </div>
                  <a
                    href={vid.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="nv-button"
                    style={{
                      backgroundColor: '#ef4444',
                      color: '#ffffff',
                      border: 'none',
                      padding: '0.45rem 0.85rem',
                      fontSize: '0.78rem',
                      fontWeight: 500,
                      gap: '0.25rem',
                      borderRadius: '8px',
                      flexShrink: 0,
                      cursor: 'pointer',
                    }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    <i className="ri-play-fill"></i> Watch
                  </a>
                </div>
              ))}
            </div>
          </SectionCard>
        )}

        <SectionCard title="Observed URLs" caption="Correlated Tabs">
          {urls.length > 0 ? (
            <div className="nv-stack" style={{ gap: '0.6rem' }}>
              {urls.map((url) => (
                <div key={url} className="flex items-center justify-between gap-2" style={{ width: '100%' }}>
                  <code className="nv-code-block" style={{ whiteSpace: 'normal', wordBreak: 'break-word', flex: 1 }}>{url}</code>
                  {url.startsWith('http') && (
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="nv-button nv-button--secondary"
                      style={{ padding: '0.25rem 0.5rem', fontSize: '11px', minHeight: 'auto', flexShrink: 0 }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <i className="ri-external-link-line"></i> Open
                    </a>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <code className="nv-code-block">No URL captured for this evidence cluster.</code>
          )}
        </SectionCard>

        {queries.length > 0 ? (
          <SectionCard title="Search Queries" caption="Intent">
            <div className="nv-stack" style={{ gap: '0.6rem' }}>
              {queries.map((query) => (
                <code key={query} className="nv-code-block" style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>{query}</code>
              ))}
            </div>
          </SectionCard>
        ) : null}

        <SectionCard title="Redacted Snippet" caption="Evidence">
          <pre className="nv-code-block">{item?.snippet_redacted || 'No textual snippet captured for this event.'}</pre>
        </SectionCard>

        {item?.threat_msg ? (
          <SectionCard title="Threat Note" caption="Detection Context">
            <p>{item.threat_msg}</p>
          </SectionCard>
        ) : null}
      </div>
    </SidePanel>
  );
};

export default WebEvidenceDrawer;

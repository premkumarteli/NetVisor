import { useState } from 'react';
import StatusBadge from '../V2/StatusBadge';

const DpiSetupGuide = ({ deviceIp, inspectionStatus }) => {
  const [activeTab, setActiveTab] = useState('all-browsers');
  const inspectionEnabled = Boolean(inspectionStatus?.inspection_enabled);
  const caInstalled = Boolean(inspectionStatus?.ca_installed);
  const browserLauncherDeprecated = Boolean(inspectionStatus?.browser_launcher_deprecated);
  const ready = inspectionEnabled && caInstalled;

  return (
    <div className="nv-stack animate-fade-in" style={{ gap: '1.25rem', backgroundColor: 'var(--nv-bg-surface-alt, rgba(0,0,0,0.02))', padding: '1.25rem', borderRadius: '16px', border: '1px dashed var(--nv-border-color, rgba(0,0,0,0.08))' }}>
      {browserLauncherDeprecated && (
        <div style={{
          padding: '1rem',
          backgroundColor: 'rgba(59, 130, 246, 0.05)',
          border: '1px solid rgba(59, 130, 246, 0.15)',
          borderRadius: '12px',
          color: 'var(--nv-text-primary)',
          display: 'flex',
          gap: '0.75rem',
          alignItems: 'flex-start'
        }}>
          <i className="ri-information-fill" style={{ color: '#3b82f6', fontSize: '1.2rem', marginTop: '-0.1rem' }}></i>
          <div>
            <strong style={{ fontSize: '0.88rem', display: 'block', marginBottom: '0.2rem' }}>Local Capture Mode Active</strong>
            <p style={{ fontSize: '0.8rem', color: '#6b7280', margin: 0, inlineSize: '100%', lineHeight: '1.4' }}>
              The agent is configured in <strong>Local Capture mode</strong>. All standard browsers (Chrome, Edge, Firefox) are intercepted automatically by the NetVisor background driver. <strong>You do not need to use the Managed Launcher wrapper or set up manual proxy extensions.</strong>
            </p>
          </div>
        </div>
      )}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div className="nv-inline-actions" style={{ margin: 0 }}>
          <StatusBadge tone={ready ? 'success' : 'warning'} icon={ready ? 'ri-check-line' : 'ri-settings-3-line'}>
            {ready ? 'Ready' : 'Setup required'}
          </StatusBadge>
          <StatusBadge tone="neutral" icon="ri-global-line">
            DPI Configuration
          </StatusBadge>
        </div>

        {/* Tab switchers */}
        <div style={{ display: 'flex', gap: '0.25rem', backgroundColor: 'rgba(0,0,0,0.05)', padding: '0.25rem', borderRadius: '8px' }}>
          <button
            type="button"
            style={{
              padding: '0.35rem 0.75rem',
              fontSize: '0.75rem',
              fontWeight: 500,
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              backgroundColor: activeTab === 'all-browsers' ? '#ffffff' : 'transparent',
              color: activeTab === 'all-browsers' ? '#111827' : '#6b7280',
              boxShadow: activeTab === 'all-browsers' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
              transition: 'all 0.15s ease'
            }}
            onClick={() => setActiveTab('all-browsers')}
          >
            <i className="ri-chrome-line" style={{ marginRight: '0.25rem' }}></i> Personal / All Browsers
          </button>
          <button
            type="button"
            style={{
              padding: '0.35rem 0.75rem',
              fontSize: '0.75rem',
              fontWeight: 500,
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              backgroundColor: activeTab === 'managed' ? '#ffffff' : 'transparent',
              color: activeTab === 'managed' ? '#111827' : '#6b7280',
              boxShadow: activeTab === 'managed' ? '0 1px 3px rgba(0,0,0,0.1)' : 'none',
              transition: 'all 0.15s ease'
            }}
            onClick={() => setActiveTab('managed')}
          >
            <i className="ri-terminal-box-line" style={{ marginRight: '0.25rem' }}></i> Managed Launcher (Chrome Wrapper)
          </button>
        </div>
      </div>

      {activeTab === 'all-browsers' ? (
        <div className="nv-grid nv-grid--two" style={{ gap: '1.5rem' }}>
          <div className="nv-stack" style={{ gap: '1rem' }}>
            <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--nv-text-primary)' }}>
              How to Inspect Personal Chrome &amp; Other Browsers
            </h4>
            <p className="nv-table__meta" style={{ fontSize: '0.85rem', lineHeight: '1.4' }}>
              You do not need the command-line chrome wrapper. You can inspect normal browsers (Chrome, Edge, Firefox) or route traffic system-wide from any browser by installing the NetVisor Root Certificate and setting up a proxy.
            </p>

            <div className="nv-insight-list" style={{ marginTop: '0.25rem' }}>
              <div className="nv-insight-item">
                <div className="nv-insight-item__icon" style={{ backgroundColor: 'rgba(45, 212, 191, 0.1)', color: '#2dd4bf' }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 'bold' }}>1</span>
                </div>
                <div className="nv-insight-item__body">
                  <strong>1. Install NetVisor Root Certificate (Trusted CA)</strong>
                  <p style={{ fontSize: '0.8rem', marginTop: '0.15rem' }}>
                    To prevent HTTPS <span style={{ color: '#ef4444' }}>&quot;Your connection is not private&quot;</span> errors, manually install and trust the NetVisor CA certificate in your browser or operating system.
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.5rem' }}>
                    <span style={{ fontSize: '0.72rem', color: '#6b7280', fontWeight: 500 }}>Certificate File Location:</span>
                    <code className="nv-code-block" style={{ fontSize: '0.72rem', padding: '0.35rem 0.5rem', wordBreak: 'break-all' }}>
                      C:\Users\prem\Network\runtime\agent\mitm\netvisor-agent-root.pem
                    </code>
                    <span style={{ fontSize: '0.72rem', color: '#6b7280', marginTop: '0.15rem' }}>
                      Double-click this file, click <strong>Install Certificate</strong>, select <strong>Local Machine</strong>, then place it under <strong>&quot;Trusted Root Certification Authorities&quot;</strong>.
                    </span>
                  </div>
                </div>
              </div>

              <div className="nv-insight-item">
                <div className="nv-insight-item__icon" style={{ backgroundColor: 'rgba(96, 165, 250, 0.1)', color: '#60a5fa' }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 'bold' }}>2</span>
                </div>
                <div className="nv-insight-item__body">
                  <strong>2. Route Your Browser Traffic (Two Options)</strong>

                  <div style={{ marginTop: '0.5rem', borderLeft: '2px solid rgba(0,0,0,0.1)', paddingLeft: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div>
                      <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#4b5563' }}>Option A: Proxy SwitchyOmega (Highly Recommended)</span>
                      <p style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '0.1rem' }}>
                        Install the free <strong>Proxy SwitchyOmega</strong> browser extension from the Chrome Web Store / Firefox Add-ons. Add a profile with:
                      </p>
                      <ul style={{ fontSize: '0.75rem', color: '#374151', listStyleType: 'disc', paddingLeft: '1rem', marginTop: '0.2rem' }}>
                        <li>Protocol: <strong>HTTP</strong></li>
                        <li>Server: <code>127.0.0.1</code></li>
                        <li>Port: <code>8899</code></li>
                      </ul>
                      <p style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '0.1rem' }}>
                        Switch the extension icon to your new profile to inspect, and switch back to &quot;Direct&quot; to stop.
                      </p>
                    </div>

                    <div style={{ marginTop: '0.25rem' }}>
                      <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#4b5563' }}>Option B: Windows System-Wide Proxy (All Browsers)</span>
                      <p style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '0.1rem' }}>
                        Route traffic from all standard browsers on your machine:
                      </p>
                      <ol style={{ fontSize: '0.75rem', color: '#374151', listStyleType: 'decimal', paddingLeft: '1rem', marginTop: '0.2rem' }}>
                        <li>Go to Windows Settings &rarr; Network &amp; Internet &rarr; <strong>Proxy</strong></li>
                        <li>Enable <strong>&quot;Use a proxy server&quot;</strong> under Manual Proxy Setup</li>
                        <li>Set Address to <code>127.0.0.1</code> and Port to <code>8899</code></li>
                        <li>Click <strong>Save</strong></li>
                      </ol>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="nv-stack" style={{ gap: '0.85rem' }}>
            <div className="nv-section__caption">Command Line Shortcut (Optional)</div>
            <p className="nv-table__meta" style={{ fontSize: '0.8rem' }}>
              If you prefer launching Chrome from a command-prompt, we also have a script that launches your personal browser profile pre-routed to the NetVisor DPI proxy:
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              <span style={{ fontSize: '0.72rem', color: '#6b7280', fontWeight: 500 }}>Run from CMD:</span>
              <code className="nv-code-block" style={{ fontSize: '0.72rem', padding: '0.5rem' }}>
                C:\Users\prem\Network\scripts\launch_personal_chrome_dpi.cmd
              </code>
              <span style={{ fontSize: '0.72rem', color: '#ef4444' }}>
                <i className="ri-error-warning-line" style={{ marginRight: '0.25rem' }}></i>
                <strong>Note:</strong> You must <strong>close all running Chrome windows</strong> before launching this script, or it will use your active direct-profile connection without routing.
              </span>
            </div>

            <div style={{ marginTop: '0.75rem', padding: '0.85rem', border: '1px solid rgba(239, 68, 68, 0.15)', backgroundColor: 'rgba(239, 68, 68, 0.02)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start' }}>
                <i className="ri-youtube-fill" style={{ color: '#ef4444', fontSize: '1.2rem', marginTop: '-0.1rem' }}></i>
                <div>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#ef4444' }}>YouTube Decoded Video Inspection</span>
                  <p style={{ fontSize: '0.75rem', color: '#374151', marginTop: '0.1rem', lineHeight: '1.4' }}>
                    Once configured, whenever you view videos on YouTube in your normal browser, the NetVisor DPI decoder will automatically extract active video titles and direct links, which you can open and watch directly from the Admin Panel.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="nv-grid nv-grid--two" style={{ gap: '1.5rem' }}>
          <div className="nv-stack" style={{ gap: '0.9rem' }}>
            <p className="nv-table__meta" style={{ fontSize: '0.86rem' }}>
              DPI visibility is available when the managed browser launcher and trusted CA are in place for device <span className="mono">{deviceIp || 'managed-agent'}</span>.
              General browsing outside the managed launcher remains outside inspection by design.
            </p>

            <div className="nv-insight-list">
              <div className="nv-insight-item">
                <div className="nv-insight-item__icon">
                  <i
                    className="ri-checkbox-circle-fill"
                    style={{ opacity: inspectionEnabled ? 1 : 0.35, color: inspectionEnabled ? '#10b981' : 'inherit' }}
                  ></i>
                </div>
                <div className="nv-insight-item__body">
                  <strong>Enable Inspection Policy</strong>
                  <p>Ensure the DPI policy is marked active for this managed host.</p>
                </div>
              </div>
              <div className="nv-insight-item">
                <div className="nv-insight-item__icon">
                  <i
                    className="ri-checkbox-circle-fill"
                    style={{ opacity: caInstalled ? 1 : 0.35, color: caInstalled ? '#10b981' : 'inherit' }}
                  ></i>
                </div>
                <div className="nv-insight-item__body">
                  <strong>Trust the CA</strong>
                  <p>The NetVisor Certificate Authority must be installed on the host.</p>
                </div>
              </div>
              <div className="nv-insight-item">
                <div className="nv-insight-item__icon">
                  <i className="ri-terminal-box-line" style={{ color: '#3b82f6' }}></i>
                </div>
                <div className="nv-insight-item__body">
                  <strong>Launch the Managed Browser</strong>
                  <p>Open the managed sandboxed browser launcher on the agent machine.</p>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <span style={{ fontSize: '0.72rem', color: '#6b7280', fontWeight: 500 }}>Launcher Command:</span>
              <code className="nv-code-block" style={{ fontSize: '0.75rem', padding: '0.5rem 0.75rem' }}>launch_chrome_netvisor.cmd</code>
            </div>
          </div>

          <div className="nv-stack" style={{ gap: '0.85rem' }}>
            <div className="nv-section__caption">Expected results</div>
            <div className="nv-pill-grid">
              <div className="nv-pill-card">
                <div className="nv-pill-card__icon">
                  <i className="ri-google-fill" style={{ color: '#4285f4' }}></i>
                </div>
                <div className="nv-pill-card__content">
                  <strong>Google Search</strong>
                  <span>&quot;Networking basics&quot;</span>
                </div>
              </div>
              <div className="nv-pill-card">
                <div className="nv-pill-card__icon">
                  <i className="ri-youtube-fill" style={{ color: '#ef4444' }}></i>
                </div>
                <div className="nv-pill-card__content">
                  <strong>YouTube Video</strong>
                  <span>&quot;How NetVisor Works&quot;</span>
                </div>
              </div>
            </div>
            <p className="nv-table__meta" style={{ fontSize: '0.8rem' }}>
              Managed DPI stays narrow by policy. The aim is evidence, not full payload retention.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default DpiSetupGuide;

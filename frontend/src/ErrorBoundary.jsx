import React from 'react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo });
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          backgroundColor: '#0a0a0a',
          color: '#ff2a2a',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: "'Inter', 'Rajdhani', sans-serif",
          padding: '2rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '600px',
            width: '100%',
            padding: '2.5rem',
            border: '1px solid rgba(255, 42, 42, 0.3)',
            boxShadow: '0 0 40px rgba(255, 42, 42, 0.1)',
            position: 'relative',
            overflow: 'hidden'
          }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '4px', background: 'repeating-linear-gradient(90deg, #ff2a2a, #ff2a2a 10px, transparent 10px, transparent 20px)' }}></div>
            
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', margin: '0 0 1rem 0', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              <i className="ri-error-warning-line" style={{ fontSize: '1.5rem' }}></i>
              System Failure Detected
            </h2>
            
            <p style={{ color: '#ffb0b0', marginBottom: '2rem', fontSize: '0.9rem', lineHeight: 1.6 }}>
              A critical rendering fault occurred in the NetVisor interface. Subsystem recovery mechanisms have been initiated.
            </p>

            <div style={{ background: 'rgba(0,0,0,0.4)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(255,42,42,0.1)', overflowX: 'auto' }}>
              <details style={{ whiteSpace: 'pre-wrap', fontSize: '0.8rem', color: '#ff8f8f', fontFamily: "'JetBrains Mono', monospace" }}>
                <summary style={{ cursor: 'pointer', outline: 'none', marginBottom: '0.5rem', fontWeight: 'bold' }}>View Diagnostic Telemetry</summary>
                <div style={{ marginTop: '1rem', opacity: 0.8 }}>
                  {this.state.error && this.state.error.toString()}
                  <br /><br />
                  {this.state.errorInfo && this.state.errorInfo.componentStack}
                </div>
              </details>
            </div>

            <button 
              onClick={() => window.location.reload()} 
              style={{
                marginTop: '2rem',
                width: '100%',
                padding: '0.8rem',
                background: 'rgba(255, 42, 42, 0.1)',
                border: '1px solid rgba(255, 42, 42, 0.3)',
                color: '#ff2a2a',
                borderRadius: '6px',
                cursor: 'pointer',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                fontWeight: 'bold',
                transition: 'all 0.2s'
              }}
              onMouseOver={(e) => { e.target.style.background = 'rgba(255, 42, 42, 0.2)'; }}
              onMouseOut={(e) => { e.target.style.background = 'rgba(255, 42, 42, 0.1)'; }}
            >
              Reboot Workspace
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

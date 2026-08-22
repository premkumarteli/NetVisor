import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { authService } from '../services/api';
import AuthSurface from '../components/V2/AuthSurface';

const LoginPage = () => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('NetVisor!DemoAccess99');
  const [showPassword, setShowPassword] = useState(false);
  const [capsLockActive, setCapsLockActive] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  
  const navigate = useNavigate();
  const location = useLocation();
  const { refreshUser } = useAuth();

  const isSessionExpired = location.state?.expired || location.search.includes('expired');

  const handleKeyDown = (e) => {
    if (e.getModifierState) {
      setCapsLockActive(e.getModifierState('CapsLock'));
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (isSubmitting) return;

    setError('');
    setIsSubmitting(true);

    try {
      await authService.login({ username, password });
      await refreshUser();
      navigate('/');
    } catch (err) {
      const detail = err.response?.data?.detail || err.response?.data?.message || err.message;
      if (detail && typeof detail === 'string') {
        setError(detail);
      } else if (err.code === 'ERR_NETWORK') {
        setError('Cannot reach NetVisor gateway. Please ensure the backend server is running on port 8000.');
      } else {
        setError('Invalid username or password. Please try again or use the demo buttons.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const autoFillDemo = (user, pass) => {
    setUsername(user);
    setPassword(pass);
    setError('');
  };

  const aside = (
    <div className="nv-auth__points">
      <div className="nv-auth__point">
        <i className="ri-key-2-line"></i>
        <div>
          <strong>Instant Demo Credentials</strong>
          <p className="mb-2">Click to load pre-configured roles instantly:</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}>
            <button
              type="button"
              onClick={() => autoFillDemo('admin', 'NetVisor!DemoAccess99')}
              className="nv-button nv-button--xs nv-button--primary"
              style={{ fontSize: '0.74rem' }}
            >
              <i className="ri-shield-user-line"></i>
              Admin (admin)
            </button>
            <button
              type="button"
              onClick={() => autoFillDemo('operator', 'NetVisor!OperatorAccess99')}
              className="nv-button nv-button--xs nv-button--secondary"
              style={{ fontSize: '0.74rem' }}
            >
              <i className="ri-user-settings-line"></i>
              Operator (operator)
            </button>
          </div>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-shield-keyhole-line"></i>
        <div>
          <strong>Cookie-based Sessions</strong>
          <p>Browser auth stays in httpOnly cookies with CSRF protection on unsafe requests.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-radar-line"></i>
        <div>
          <strong>Signed Endpoint Traffic</strong>
          <p>Agents and gateways use signed transport so the control plane can trust the source.</p>
        </div>
      </div>
    </div>
  );

  return (
    <AuthSurface
      eyebrow="Authentication"
      title="NetVisor SOC Login"
      description="Sign in to the operational security workspace. Default demo credentials are ready below for 1-click access."
      badge="Protected session"
      asideTitle="Quick Workspace Access"
      asideCaption="Control plane"
      aside={aside}
      footer={(
        <>
          <span>Need an account for your organization?</span>
          <Link className="nv-auth__link" to="/register">Create account</Link>
        </>
      )}
    >
      {isSessionExpired && !error ? (
        <div className="nv-auth__error" style={{ background: 'rgba(251, 191, 36, 0.12)', borderColor: 'rgba(251, 191, 36, 0.3)', color: '#fbbf24' }}>
          <i className="ri-time-line"></i>
          <span>Your previous session has expired. Please sign in again to continue.</span>
        </div>
      ) : null}

      {error ? (
        <div className="nv-auth__error" role="alert">
          <i className="ri-error-warning-line"></i>
          <span>{error}</span>
        </div>
      ) : null}

      <form onSubmit={handleLogin} className="nv-auth__form">
        <label className="nv-auth__field">
          <span className="nv-auth__label">Username or Email</span>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <input
              type="text"
              className="nv-auth__input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              disabled={isSubmitting}
              placeholder="Enter username or email"
            />
            {username ? (
              <button
                type="button"
                onClick={() => setUsername('')}
                tabIndex={-1}
                style={{
                  position: 'absolute',
                  right: '0.75rem',
                  background: 'none',
                  border: 'none',
                  color: 'var(--nv-text-muted)',
                  cursor: 'pointer',
                }}
                title="Clear username"
              >
                <i className="ri-close-circle-line"></i>
              </button>
            ) : null}
          </div>
        </label>

        <label className="nv-auth__field">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="nv-auth__label">Password</span>
            {capsLockActive ? (
              <span style={{ fontSize: '0.7rem', color: '#fbbf24', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <i className="ri-caps-lock-line"></i> Caps Lock is ON
              </span>
            ) : null}
          </div>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <input
              type={showPassword ? 'text' : 'password'}
              className="nv-auth__input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={handleKeyDown}
              onKeyUp={handleKeyDown}
              autoComplete="current-password"
              required
              disabled={isSubmitting}
              placeholder="Enter password"
            />
            <button
              type="button"
              onClick={() => setShowPassword((prev) => !prev)}
              tabIndex={-1}
              style={{
                position: 'absolute',
                right: '0.75rem',
                background: 'none',
                border: 'none',
                color: 'var(--nv-text-muted)',
                cursor: 'pointer',
                fontSize: '1.1rem',
              }}
              title={showPassword ? 'Hide password' : 'Show password'}
            >
              <i className={showPassword ? 'ri-eye-off-line' : 'ri-eye-line'}></i>
            </button>
          </div>
        </label>

        <div style={{
          padding: '0.75rem 1rem',
          borderRadius: '12px',
          background: 'rgba(84, 200, 232, 0.06)',
          border: '1px solid rgba(84, 200, 232, 0.16)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          fontSize: '0.76rem',
          color: 'var(--nv-text-soft)',
        }}>
          <i className="ri-information-line" style={{ fontSize: '1.2rem', color: 'var(--nv-accent, #54c8e8)', flexShrink: 0 }}></i>
          <div>
            <strong style={{ color: 'var(--nv-text)', display: 'block', marginBottom: '0.1rem' }}>Demo Credentials Ready</strong>
            <span>Click the Admin or Operator buttons on the right to prefill credentials instantly.</span>
          </div>
        </div>

        <div className="nv-auth__footer" style={{ marginTop: '0.5rem' }}>
          <button
            type="submit"
            className="nv-button nv-button--primary"
            disabled={isSubmitting}
            style={{ opacity: isSubmitting ? 0.7 : 1 }}
          >
            {isSubmitting ? (
              <>
                <i className="ri-loader-4-line animate-spin"></i>
                Signing In...
              </>
            ) : (
              <>
                <i className="ri-login-box-line"></i>
                Sign In
              </>
            )}
          </button>
          <span>Managed SOC Console</span>
        </div>
      </form>
    </AuthSurface>
  );
};

export default LoginPage;

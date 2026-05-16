import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { authService } from '../services/api';
import AuthSurface from '../components/V2/AuthSurface';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();
  const { refreshUser } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await authService.login({ username, password });
      await refreshUser();
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Connection error');
    } finally {
      setLoading(false);
    }
  };

  const aside = (
    <div className="nv-auth__points">
      <div className="nv-auth__point">
        <div className="nv-auth__point-icon">
          <i className="ri-shield-keyhole-line" />
        </div>
        <div>
          <strong>Cookie-based sessions</strong>
          <p>Browser auth stays in httpOnly cookies with CSRF protection on unsafe requests.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <div className="nv-auth__point-icon">
          <i className="ri-radar-line" />
        </div>
        <div>
          <strong>Signed endpoint traffic</strong>
          <p>Agents and gateways use signed transport so the control plane can trust the source.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <div className="nv-auth__point-icon">
          <i className="ri-navigation-line" />
        </div>
        <div>
          <strong>DPI stays managed</strong>
          <p>Inspection remains explicit opt-in on managed devices only.</p>
        </div>
      </div>
    </div>
  );

  return (
    <AuthSurface
      eyebrow="Secure access"
      title="Welcome Back"
      description="Sign in to the NetVisor operational workspace. Your session is protected by encrypted cookies, CSRF tokens, and server-side validation."
      badge="Protected session"
      asideTitle="Why this workspace is different"
      asideCaption="Control plane"
      aside={aside}
      footer={(
        <>
          <span>Request access from an administrator if you do not have an account.</span>
          <Link className="nv-auth__link" to="/register">
            <i className="ri-arrow-right-line" />
            Create account
          </Link>
        </>
      )}
    >
      {error ? (
        <div className="nv-auth__error" role="alert">
          <div className="nv-auth__error-icon">
            <i className="ri-error-warning-line" />
          </div>
          <div className="nv-auth__error-content">
            <strong>Authentication failed</strong>
            <span>{error}</span>
          </div>
        </div>
      ) : null}

      <form onSubmit={handleLogin} className="nv-auth__form">
        <label className="nv-auth__field" id="login-username-field">
          <span className="nv-auth__label">
            <i className="ri-user-3-line" />
            Username
          </span>
          <div className="nv-auth__input-wrapper">
            <input
              type="text"
              className="nv-auth__input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              placeholder="Enter your username"
              required
            />
          </div>
        </label>

        <label className="nv-auth__field" id="login-password-field">
          <span className="nv-auth__label">
            <i className="ri-lock-password-line" />
            Password
          </span>
          <div className="nv-auth__input-wrapper">
            <input
              type={showPassword ? 'text' : 'password'}
              className="nv-auth__input nv-auth__input--password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              placeholder="Enter your password"
              required
            />
            <button
              type="button"
              className="nv-auth__visibility-toggle"
              onClick={() => setShowPassword(!showPassword)}
              tabIndex={-1}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              <i className={showPassword ? 'ri-eye-off-line' : 'ri-eye-line'} />
            </button>
          </div>
        </label>

        <div className="nv-auth__actions">
          <button
            type="submit"
            className="nv-button nv-button--primary nv-auth__submit"
            disabled={loading}
            id="login-submit-btn"
          >
            {loading ? (
              <>
                <span className="nv-auth__spinner" />
                Authenticating...
              </>
            ) : (
              <>
                <i className="ri-login-box-line" />
                Sign In
              </>
            )}
          </button>
          <span className="nv-auth__access-note">
            <i className="ri-information-line" />
            Managed access only
          </span>
        </div>
      </form>
    </AuthSurface>
    );
};

export default LoginPage;

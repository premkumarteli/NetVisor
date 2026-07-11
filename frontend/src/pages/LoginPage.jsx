import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { authService } from '../services/api';
import AuthSurface from '../components/V2/AuthSurface';

const LoginPage = () => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('NetVisor!DemoAccess99');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { refreshUser } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await authService.login({ username, password });
      await refreshUser();
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Connection error');
    }
  };

  const autoFillDemo = (user, pass) => {
    setUsername(user);
    setPassword(pass);
  };

  const aside = (
    <div className="nv-auth__points">
      <div className="nv-auth__point">
        <i className="ri-key-2-line"></i>
        <div>
          <strong>Demo Access Credentials</strong>
          <p className="mb-2">Sign in using these pre-configured credentials:</p>
          <div className="flex flex-wrap gap-2 mt-2">
            <button
              type="button"
              onClick={() => autoFillDemo('admin', 'NetVisor!DemoAccess99')}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 transition-all"
            >
              Admin (admin / NetVisor!DemoAccess99)
            </button>
            <button
              type="button"
              onClick={() => autoFillDemo('operator', 'NetVisor!OperatorAccess99')}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/20 transition-all"
            >
              Operator (operator / NetVisor!OperatorAccess99)
            </button>
          </div>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-shield-keyhole-line"></i>
        <div>
          <strong>Cookie-based sessions</strong>
          <p>Browser auth stays in httpOnly cookies with CSRF protection on unsafe requests.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-radar-line"></i>
        <div>
          <strong>Signed endpoint traffic</strong>
          <p>Agents and gateways use signed transport so the control plane can trust the source.</p>
        </div>
      </div>
    </div>
  );

  return (
    <AuthSurface
      eyebrow="Secure access"
      title="NetVisor Login"
      description="Sign in to the operational workspace. Default demo credentials have been automatically pre-filled below for seamless instant access."
      badge="Protected session"
      asideTitle="Quick Workspace Access"
      asideCaption="Control plane"
      aside={aside}
      footer={(
        <>
          <span>Request access from an administrator if you do not have an account.</span>
          <Link className="nv-auth__link" to="/register">Create account</Link>
        </>
      )}
    >
      {error ? (
        <div className="nv-auth__error" role="alert">
          <i className="ri-error-warning-line"></i>
          <span>{error}</span>
        </div>
      ) : null}

      <form onSubmit={handleLogin} className="nv-auth__form">
        <label className="nv-auth__field">
          <span className="nv-auth__label">Username or email</span>
          <input
            type="text"
            className="nv-auth__input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
        </label>

        <label className="nv-auth__field">
          <span className="nv-auth__label">Password</span>
          <input
            type="password"
            className="nv-auth__input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>

        <div className="p-3.5 mb-2 rounded-xl bg-cyan-500/5 border border-cyan-500/10 text-xs text-cyan-300 flex items-center gap-3">
          <i className="ri-information-line text-lg text-cyan-400"></i>
          <div>
            <span className="font-semibold block">Credentials Pre-filled</span>
            <span>Use the buttons on the right to quickly switch between accounts.</span>
          </div>
        </div>

        <div className="nv-auth__footer">
          <button type="submit" className="nv-button nv-button--primary">
            <i className="ri-login-box-line"></i>
            Sign In
          </button>
          <span>Managed access only</span>
        </div>
      </form>
    </AuthSurface>
  );
};

export default LoginPage;

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authService } from '../services/api';
import AuthSurface from '../components/V2/AuthSurface';

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirm_password: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (isSubmitting) return;
    setError('');

    if (formData.password !== formData.confirm_password) {
      setError('Passwords do not match. Please re-enter your password.');
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setIsSubmitting(true);
    try {
      await authService.register(formData);
      navigate('/login', { state: { registered: true } });
    } catch (err) {
      const detail = err.response?.data?.detail || err.response?.data?.message || err.message;
      if (detail && typeof detail === 'string') {
        setError(detail);
      } else if (err.code === 'ERR_NETWORK') {
        setError('Cannot reach NetVisor gateway. Please ensure backend is running.');
      } else {
        setError('Registration failed. Please check your inputs or try another username.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const aside = (
    <div className="nv-auth__points">
      <div className="nv-auth__point">
        <i className="ri-user-3-line"></i>
        <div>
          <strong>Role-Based Access Control</strong>
          <p>Registration matches your organization's policy and access tiers assigned by an administrator.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-lock-password-line"></i>
        <div>
          <strong>Strong Password Standards</strong>
          <p>Account credentials are protected by server-side session cookies and cryptographic hashing.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-shield-star-line"></i>
        <div>
          <strong>Operational Review</strong>
          <p>Admin verification is required for privileged control plane and deep packet inspection access.</p>
        </div>
      </div>
    </div>
  );

  return (
    <AuthSurface
      eyebrow="Onboarding"
      title="Create Account"
      description="Register an account for the NetVisor security workspace."
      badge="New Analyst"
      asideTitle="Access Guidelines"
      asideCaption="Security model"
      aside={aside}
      footer={(
        <>
          <span>Already registered?</span>
          <Link className="nv-auth__link" to="/login">Back to Sign In</Link>
        </>
      )}
    >
      {error ? (
        <div className="nv-auth__error" role="alert">
          <i className="ri-error-warning-line"></i>
          <span>{error}</span>
        </div>
      ) : null}

      <form onSubmit={handleRegister} className="nv-auth__form">
        <label className="nv-auth__field">
          <span className="nv-auth__label">Username</span>
          <input
            type="text"
            name="username"
            className="nv-auth__input"
            value={formData.username}
            onChange={handleChange}
            autoComplete="username"
            required
            disabled={isSubmitting}
            placeholder="Choose username"
          />
        </label>

        <label className="nv-auth__field">
          <span className="nv-auth__label">Email</span>
          <input
            type="email"
            name="email"
            className="nv-auth__input"
            value={formData.email}
            onChange={handleChange}
            autoComplete="email"
            required
            disabled={isSubmitting}
            placeholder="user@organization.com"
          />
        </label>

        <label className="nv-auth__field">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="nv-auth__label">Password</span>
          </div>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <input
              type={showPassword ? 'text' : 'password'}
              name="password"
              className="nv-auth__input"
              value={formData.password}
              onChange={handleChange}
              autoComplete="new-password"
              required
              disabled={isSubmitting}
              placeholder="Minimum 8 characters"
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

        <label className="nv-auth__field">
          <span className="nv-auth__label">Confirm Password</span>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <input
              type={showPassword ? 'text' : 'password'}
              name="confirm_password"
              className="nv-auth__input"
              value={formData.confirm_password}
              onChange={handleChange}
              autoComplete="new-password"
              required
              disabled={isSubmitting}
              placeholder="Re-enter password"
            />
          </div>
        </label>

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
                Creating Account...
              </>
            ) : (
              <>
                <i className="ri-user-add-line"></i>
                Register Account
              </>
            )}
          </button>
          <Link className="nv-auth__link" to="/login">Back to Sign In</Link>
        </div>
      </form>
    </AuthSurface>
  );
};

export default RegisterPage;

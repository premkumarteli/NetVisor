import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authService } from "../services/api";
import AuthSurface from '../components/V2/AuthSurface';

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirm_password: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirm_password) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      await authService.register(formData);
      navigate('/login');
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.message || err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const aside = (
    <div className="nv-auth__points">
      <div className="nv-auth__point">
        <div className="nv-auth__point-icon">
          <i className="ri-user-3-line" />
        </div>
        <div>
          <strong>One account, one role</strong>
          <p>Registration should match the workspace policy and the access level assigned by an administrator.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <div className="nv-auth__point-icon">
          <i className="ri-lock-password-line" />
        </div>
        <div>
          <strong>Use a strong password</strong>
          <p>Account access is protected by server-side session cookies and CSRF checks after login.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <div className="nv-auth__point-icon">
          <i className="ri-shield-star-line" />
        </div>
        <div>
          <strong>Operational review</strong>
          <p>Admin review is still expected for system-level, DPI, and fleet access.</p>
        </div>
      </div>
    </div>
  );

  return (
    <AuthSurface
      eyebrow="Account onboarding"
      title="Create Account"
      description="Set up your workspace credentials. Your account will follow the access model configured by the workspace administrator."
      badge="Onboarding"
      asideTitle="Before you register"
      asideCaption="Access model"
      aside={aside}
      footer={(
        <>
          <span>Already have access?</span>
          <Link className="nv-auth__link" to="/login">
            <i className="ri-arrow-left-line" />
            Back to login
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
            <strong>Registration failed</strong>
            <span>{error}</span>
          </div>
        </div>
      ) : null}

      <form onSubmit={handleRegister} className="nv-auth__form">
        <label className="nv-auth__field" id="register-username-field">
          <span className="nv-auth__label">
            <i className="ri-user-3-line" />
            Username
          </span>
          <div className="nv-auth__input-wrapper">
            <input
              type="text"
              name="username"
              className="nv-auth__input"
              value={formData.username}
              onChange={handleChange}
              autoComplete="username"
              placeholder="Choose a username"
              required
            />
          </div>
        </label>

        <label className="nv-auth__field" id="register-email-field">
          <span className="nv-auth__label">
            <i className="ri-mail-line" />
            Email
          </span>
          <div className="nv-auth__input-wrapper">
            <input
              type="email"
              name="email"
              className="nv-auth__input"
              value={formData.email}
              onChange={handleChange}
              autoComplete="email"
              placeholder="Enter your email"
              required
            />
          </div>
        </label>

        <div className="nv-auth__field-row">
          <label className="nv-auth__field" id="register-password-field">
            <span className="nv-auth__label">
              <i className="ri-lock-password-line" />
              Password
            </span>
            <div className="nv-auth__input-wrapper">
              <input
                type={showPassword ? 'text' : 'password'}
                name="password"
                className="nv-auth__input nv-auth__input--password"
                value={formData.password}
                onChange={handleChange}
                autoComplete="new-password"
                placeholder="Create a password"
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

          <label className="nv-auth__field" id="register-confirm-password-field">
            <span className="nv-auth__label">
              <i className="ri-lock-line" />
              Confirm password
            </span>
            <div className="nv-auth__input-wrapper">
              <input
                type={showPassword ? 'text' : 'password'}
                name="confirm_password"
                className="nv-auth__input nv-auth__input--password"
                value={formData.confirm_password}
                onChange={handleChange}
                autoComplete="new-password"
                placeholder="Confirm your password"
                required
              />
            </div>
          </label>
        </div>

        <div className="nv-auth__actions">
          <button
            type="submit"
            className="nv-button nv-button--primary nv-auth__submit"
            disabled={loading}
            id="register-submit-btn"
          >
            {loading ? (
              <>
                <span className="nv-auth__spinner" />
                Creating account...
              </>
            ) : (
              <>
                <i className="ri-user-add-line" />
                Register
              </>
            )}
          </button>
          <Link className="nv-auth__link" to="/login">
            <i className="ri-arrow-left-line" />
            Back to login
          </Link>
        </div>
      </form>
    </AuthSurface>
  );
};

export default RegisterPage;

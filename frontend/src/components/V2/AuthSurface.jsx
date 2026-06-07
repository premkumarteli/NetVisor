import SectionCard from './SectionCard';
import StatusBadge from './StatusBadge';

const AuthSurface = ({
  eyebrow = 'Secure access',
  title,
  description,
  badge = 'Protected session',
  asideTitle = 'Workspace posture',
  asideCaption = 'Operational notes',
  aside,
  footer,
  children,
}) => (
  <div className="nv-auth">
    {/* Animated background scene */}
    <div className="nv-auth__scene" aria-hidden="true">
      <div className="nv-auth__orb nv-auth__orb--primary" />
      <div className="nv-auth__orb nv-auth__orb--secondary" />
      <div className="nv-auth__orb nv-auth__orb--tertiary" />
      <div className="nv-auth__ring nv-auth__ring--outer" />
      <div className="nv-auth__ring nv-auth__ring--inner" />
      <div className="nv-auth__grid-overlay" />
    </div>

    <div className="nv-auth__shell">
      {/* Logo header */}
      <div className="nv-auth__brand">
        <div className="nv-auth__brand-icon">
          <i className="ri-shield-keyhole-line" />
        </div>
        <span className="nv-auth__brand-name">NetVisor</span>
        <span className="nv-auth__brand-tag">Security Workspace</span>
      </div>

      <div className="nv-auth__columns">
        <SectionCard
          className="nv-auth__card"
          caption={eyebrow}
          title={title}
          aside={<StatusBadge tone="accent" icon="ri-shield-keyhole-line">{badge}</StatusBadge>}
        >
          {description ? <p className="nv-auth__description">{description}</p> : null}
          <div className="nv-auth__body">{children}</div>
          {footer ? <div className="nv-auth__footer">{footer}</div> : null}
        </SectionCard>

        {aside ? (
          <SectionCard className="nv-auth__aside" caption={asideCaption} title={asideTitle}>
            <div className="nv-auth__aside-body">{aside}</div>
          </SectionCard>
        ) : null}
      </div>

      {/* Bottom trust bar */}
      <div className="nv-auth__trust-bar">
        <div className="nv-auth__trust-item">
          <i className="ri-lock-line" />
          <span>TLS Encrypted</span>
        </div>
        <div className="nv-auth__trust-divider" />
        <div className="nv-auth__trust-item">
          <i className="ri-fingerprint-line" />
          <span>Session Protected</span>
        </div>
        <div className="nv-auth__trust-divider" />
        <div className="nv-auth__trust-item">
          <i className="ri-shield-check-line" />
          <span>CSRF Guarded</span>
        </div>
      </div>
    </div>
  </div>
);

export default AuthSurface;

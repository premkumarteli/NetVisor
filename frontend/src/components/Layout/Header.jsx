import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useImmersion } from '../../immersion/engine/useImmersion';
import { useVisibilityPolling } from '../../hooks/useVisibilityPolling';
import { systemService } from '../../services/api';
import Breadcrumbs from './Breadcrumbs';
import GlobalSearch from './GlobalSearch';
import StatusBadge from '../V2/StatusBadge';

const routeMeta = [
  { match: (path) => path === '/dashboard' || path === '/', title: 'Operational Overview', subtitle: 'Real-time posture and triage' },
  { match: (path) => path === '/devices', title: 'Device Inventory', subtitle: 'Managed and observed assets' },
  { match: (path) => path.startsWith('/apps'), title: 'Application Coverage', subtitle: 'Traffic grouped by product usage' },
  { match: (path) => path === '/threats', title: 'Threat Investigation', subtitle: 'Active high-risk detections' },
  { match: (path) => path === '/activity', title: 'Traffic Activity', subtitle: 'Live session visibility' },
  { match: (path) => path === '/logs', title: 'Flow Logs', subtitle: 'Search and export flow records' },
  { match: (path) => path === '/agents' || path.startsWith('/agents/'), title: 'Fleet Operations', subtitle: 'Agent health and device coverage' },
  { match: (path) => path === '/vpn', title: 'VPN Risk Feed', subtitle: 'Tunnel and proxy detections' },
  { match: (path) => path === '/settings/appearance', title: 'Workspace Store', subtitle: 'Theme environments and visual fidelity' },
  { match: (path) => path === '/settings', title: 'System Controls', subtitle: 'Runtime and maintenance controls' },
  { match: (path) => path === '/dpi', title: 'Web Inspection', subtitle: 'Global browser visibility' },
  { match: (path) => path === '/user', title: 'My Security Workspace', subtitle: 'Account posture and linked telemetry' },
  { match: (path) => path.startsWith('/user/'), title: 'Device Workspace', subtitle: 'Evidence-first device investigation' },
];

const Header = ({ onToggleAlerts, onToggleNav }) => {
  const { user, isAdmin, logout } = useAuth();
  const [systemHealth, setSystemHealth] = useState({
    status: 'Operational',
  });
  const [menuOpen, setMenuOpen] = useState(false);
  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const { themeId, activeTheme, changeTheme, themesList } = useImmersion();
  const menuRef = useRef(null);
  const themeMenuRef = useRef(null);
  const navigate = useNavigate();
  const location = useLocation();

  const activeRoute = useMemo(
    () => routeMeta.find((entry) => entry.match(location.pathname)) || { title: 'NetVisor', subtitle: 'Security workspace' },
    [location.pathname],
  );



  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false);
      }
      if (themeMenuRef.current && !themeMenuRef.current.contains(event.target)) {
        setThemeMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await systemService.getHealth();
      setSystemHealth({
        status: res.data?.status === 'healthy' ? 'Operational' : 'Degraded',
      });
    } catch {
      setSystemHealth({
        status: 'Degraded',
      });
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  useVisibilityPolling(fetchHealth, 30000);



  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const displayUser = user || { username: 'Guest', role: 'viewer' };

  return (
    <header className="nv-topbar">
      <div className="nv-topbar__cluster">
        <button type="button" className="nv-button nv-button--secondary" onClick={onToggleNav}>
          <i className="ri-menu-line"></i>
        </button>
        <div className="nv-topbar__title">
          <Breadcrumbs />
          <strong>{activeRoute.title}</strong>
          <span>{activeRoute.subtitle}</span>
        </div>
      </div>

      <GlobalSearch />

      <div className="nv-topbar__cluster">
        <StatusBadge tone={systemHealth.status === 'Operational' ? 'success' : 'warning'} icon="ri-pulse-line">
          {systemHealth.status}
        </StatusBadge>
        <button type="button" className="nv-button nv-button--secondary" onClick={onToggleAlerts} title="Threat feed">
          <i className="ri-notification-3-line"></i>
        </button>
        <div className="nv-theme-switcher" ref={themeMenuRef}>
          <button type="button" className="nv-button nv-button--secondary nv-theme-trigger" onClick={() => setThemeMenuOpen((curr) => !curr)} title="Workspace Mode">
            <i className="ri-palette-line"></i>
            <span>{activeTheme.label}</span>
          </button>

          {themeMenuOpen ? (
            <div className="nv-menu nv-theme-menu">
              <div className="nv-menu__section">
                <div className="nv-menu__label">Immersion Engine</div>
                <p>Choose an operational environment.</p>
              </div>
              {themesList.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className={`nv-theme-card ${themeId === t.id ? 'is-active' : ''}`.trim()}
                  onClick={() => { changeTheme(t.id); setThemeMenuOpen(false); }}
                  style={{ '--theme-preview': t.preview?.gradient, '--theme-preview-primary': t.preview?.primary }}
                >
                  <span className="nv-theme-card__preview" aria-hidden="true"></span>
                  <span className="nv-theme-card__copy">
                    <strong>
                      <i className={t.icon || 'ri-palette-line'}></i>
                      {t.label}
                    </strong>
                    <span>{t.description || 'Workspace mode'}</span>
                  </span>
                  <span className="nv-theme-card__meta">{t.category}</span>
                  {themeId === t.id && <i className="ri-check-line nv-theme-card__check"></i>}
                </button>
              ))}
            </div>
          ) : null}
        </div>

        <div style={{ position: 'relative' }} ref={menuRef}>
          <button type="button" className="nv-user-pill" onClick={() => setMenuOpen((current) => !current)}>
            <div className="nv-user-pill__avatar">{displayUser.username?.[0]?.toUpperCase() || 'U'}</div>
            <div className="nv-topbar__title" style={{ gap: '0.1rem', textAlign: 'left' }}>
              <strong>{displayUser.username}</strong>
              <span>{displayUser.role}</span>
            </div>
            <i className={`ri-arrow-down-s-line ${menuOpen ? 'rotate-180' : ''}`}></i>
          </button>

          {menuOpen ? (
            <div className="nv-menu">
              <div className="nv-menu__section">
                <div className="nv-menu__label">Session</div>
              </div>
              <button type="button" className="nv-menu__item" onClick={() => navigate('/user')}>
                <i className="ri-shield-user-line"></i>
                <span>Open personal workspace</span>
              </button>
              {isAdmin ? (
                <button type="button" className="nv-menu__item" onClick={() => navigate('/settings')}>
                  <i className="ri-settings-4-line"></i>
                  <span>Open system settings</span>
                </button>
              ) : null}
              <div className="nv-menu__section">
                <div className="nv-menu__label">Connection</div>
                <p>{window.location.hostname}</p>
              </div>
              <button type="button" className="nv-menu__item" onClick={handleLogout}>
                <i className="ri-logout-box-r-line"></i>
                <span>Logout</span>
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
};

export default Header;

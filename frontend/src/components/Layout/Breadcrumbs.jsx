import { Link, useLocation } from 'react-router-dom';
import { useImmersion } from '../../immersion/engine/useImmersion';

const Breadcrumbs = () => {
  const location = useLocation();
  const { activeTheme } = useImmersion();
  const pathnames = location.pathname.split('/').filter((x) => x);

  if (pathnames.length === 0) return null;

  return (
    <nav aria-label="Breadcrumb">
      <ol style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', padding: 0, margin: 0, listStyle: 'none' }}>
        <li style={{ display: 'inline-flex', alignItems: 'center' }}>
          <Link to="/" style={{ color: 'var(--nv-text-muted)', fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            <i className="ri-home-4-line" style={{ marginRight: '0.3rem' }}></i> Home
          </Link>
        </li>
        {pathnames.map((value, index) => {
          const last = index === pathnames.length - 1;
          const to = `/${pathnames.slice(0, index + 1).join('/')}`;
          
          const segmentName = decodeURIComponent(value).replace(/-/g, ' ');
          const termKey = segmentName.toLowerCase();
          const immersionTerm = activeTheme?.terminology?.[termKey];
          const displayText = immersionTerm ? `${segmentName} (${immersionTerm})` : segmentName;

          return (
            <li key={to} style={{ display: 'inline-flex', alignItems: 'center' }}>
              <i className="ri-arrow-right-s-line" style={{ color: 'var(--nv-text-muted)', opacity: 0.45 }}></i>
              {last ? (
                <span style={{ color: 'var(--nv-accent)', fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  {displayText}
                </span>
              ) : (
                <Link to={to} style={{ color: 'var(--nv-text-muted)', fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  {displayText}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
};

export default Breadcrumbs;

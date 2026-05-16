import { useEffect, useMemo, useState } from 'react';
import PageHeader from '../components/V2/PageHeader';
import StatusBadge from '../components/V2/StatusBadge';
import { useImmersion } from '../immersion/engine/useImmersion';

const performanceTiers = [
  {
    id: 'minimal',
    label: 'Minimal',
    description: 'Disables heavier ambient renderers for low-power systems.',
    icon: 'ri-speed-mini-line',
  },
  {
    id: 'standard',
    label: 'Standard',
    description: 'Balanced visual effects for daily monitoring.',
    icon: 'ri-dashboard-3-line',
  },
  {
    id: 'cinematic',
    label: 'Cinematic',
    description: 'Maximum atmosphere for demos and high-end systems.',
    icon: 'ri-movie-2-line',
  },
];

const ThemeStorePage = () => {
  const {
    themeId,
    activeTheme,
    themesList,
    changeTheme,
    performanceTier,
    setPerformanceTier,
  } = useImmersion();
  const [selectedThemeId, setSelectedThemeId] = useState(themeId);
  const [categoryFilter, setCategoryFilter] = useState('all');

  useEffect(() => {
    setSelectedThemeId(themeId);
  }, [themeId]);

  const orderedThemes = useMemo(() => {
    const flagshipThemes = themesList.filter((theme) => theme.category === 'flagship');
    const otherThemes = themesList.filter((theme) => theme.category !== 'flagship');
    return [...flagshipThemes, ...otherThemes];
  }, [themesList]);

  const categories = useMemo(() => {
    const themeCategories = Array.from(new Set(orderedThemes.map((theme) => theme.category)));
    return ['all', ...themeCategories];
  }, [orderedThemes]);

  const selectedTheme = orderedThemes.find((theme) => theme.id === selectedThemeId) || activeTheme;
  const visibleThemes = categoryFilter === 'all'
    ? orderedThemes
    : orderedThemes.filter((theme) => theme.category === categoryFilter);
  const enabledEffects = Object.entries(selectedTheme?.effects || {})
    .filter(([, value]) => Boolean(value))
    .map(([key]) => key.replace(/([A-Z])/g, ' $1').toLowerCase());
  const sceneStrip = selectedTheme?.scene?.strip || [];

  return (
    <div className="nv-page workspace-store">
      <PageHeader
        eyebrow="Settings"
        title="Workspace Store"
        description="Browse and apply internal NetVisor operational environments. V1 uses safe CSS-generated visuals and local persistence."
        actions={(
          <StatusBadge tone="accent" icon={activeTheme?.icon || 'ri-palette-line'}>
            {activeTheme?.label || 'NetVisor Core'}
          </StatusBadge>
        )}
      />

      <section className="workspace-store__hero">
        <div
          className="workspace-store__preview workspace-store__preview--large"
          style={{
            '--workspace-preview': selectedTheme?.preview?.gradient,
            '--workspace-preview-primary': selectedTheme?.preview?.primary,
          }}
        >
          <span></span>
          <span></span>
          <span></span>
          <div className="workspace-store__preview-caption">
            <i className={selectedTheme?.icon || 'ri-palette-line'}></i>
            <strong>{selectedTheme?.scene?.signature || selectedTheme?.label}</strong>
          </div>
        </div>
        <div>
          <div className="cinematic-kicker">Environment Preview</div>
          <h2>{selectedTheme?.scene?.headline || selectedTheme?.label || 'NetVisor Core'}</h2>
          <p>{selectedTheme?.scene?.description || selectedTheme?.description || 'Balanced NetVisor workspace.'}</p>
          <div className="workspace-store__meta">
            <StatusBadge tone="accent" icon="ri-cpu-line">GPU {selectedTheme?.gpuCost || 'low'}</StatusBadge>
            <StatusBadge tone="neutral" icon="ri-sparkling-line">{selectedTheme?.category || 'standard'}</StatusBadge>
            {selectedTheme?.id === themeId ? (
              <StatusBadge tone="success" icon="ri-check-line">Applied</StatusBadge>
            ) : null}
          </div>
          <div className="workspace-store__scene-strip">
            {sceneStrip.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
          <div className="workspace-store__effects">
            {(enabledEffects.length ? enabledEffects : ['clean mode']).map((effect) => (
              <span key={effect}>{effect}</span>
            ))}
          </div>
          <div className="workspace-store__hero-actions">
            <button
              type="button"
              className="nv-button nv-button--primary"
              onClick={() => changeTheme(selectedTheme.id)}
              disabled={selectedTheme?.id === themeId}
            >
              <i className={selectedTheme?.id === themeId ? 'ri-check-line' : 'ri-palette-line'}></i>
              {selectedTheme?.id === themeId ? 'Workspace Applied' : 'Apply Selected Workspace'}
            </button>
            <button
              type="button"
              className="nv-button nv-button--secondary"
              onClick={() => setSelectedThemeId(themeId)}
              disabled={selectedTheme?.id === themeId}
            >
              <i className="ri-arrow-go-back-line"></i>
              Return to Current
            </button>
          </div>
        </div>
      </section>

      <section className="workspace-store__section">
        <div className="workspace-store__section-header">
          <div>
            <div className="cinematic-kicker">Visual Fidelity</div>
            <h2>Performance Tier</h2>
          </div>
          <span>Saved locally on this browser</span>
        </div>
        <div className="workspace-store__tier-grid">
          {performanceTiers.map((tier) => (
            <button
              key={tier.id}
              type="button"
              className={`workspace-tier ${performanceTier === tier.id ? 'is-active' : ''}`.trim()}
              onClick={() => setPerformanceTier(tier.id)}
            >
              <i className={tier.icon}></i>
              <strong>{tier.label}</strong>
              <span>{tier.description}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="workspace-store__section">
        <div className="workspace-store__section-header">
          <div>
            <div className="cinematic-kicker">Theme Catalog</div>
            <h2>Operational Environments</h2>
          </div>
          <span>{visibleThemes.length} / {orderedThemes.length} internal modes</span>
        </div>

        <div className="workspace-store__filters" role="tablist" aria-label="Filter workspace modes">
          {categories.map((category) => (
            <button
              key={category}
              type="button"
              className={categoryFilter === category ? 'is-active' : ''}
              onClick={() => setCategoryFilter(category)}
            >
              {category === 'all' ? 'All' : category}
            </button>
          ))}
        </div>

        <div className="workspace-store__grid">
          {visibleThemes.map((theme) => {
            const isActive = theme.id === themeId;
            const isSelected = theme.id === selectedTheme?.id;
            return (
              <article
                key={theme.id}
                className={`workspace-theme-card ${isActive ? 'is-active' : ''} ${isSelected ? 'is-selected' : ''}`.trim()}
                style={{
                  '--workspace-preview': theme.preview?.gradient,
                  '--workspace-preview-primary': theme.preview?.primary,
                }}
                onClick={() => setSelectedThemeId(theme.id)}
              >
                <div className="workspace-theme-card__preview">
                  <span></span>
                  <span></span>
                </div>
                <div className="workspace-theme-card__body">
                  <div className="workspace-theme-card__title">
                    <i className={theme.icon || 'ri-palette-line'}></i>
                    <strong>{theme.label}</strong>
                  </div>
                  <p>{theme.description || 'Workspace mode'}</p>
                  <div className="workspace-theme-card__badges">
                    <span>{theme.category}</span>
                    <span>GPU {theme.gpuCost || 'low'}</span>
                  </div>
                </div>
                <button
                  type="button"
                  className={`nv-button ${isActive ? 'nv-button--secondary' : 'nv-button--primary'}`}
                  onClick={(event) => {
                    event.stopPropagation();
                    changeTheme(theme.id);
                  }}
                  disabled={isActive}
                >
                  <i className={isActive ? 'ri-check-line' : 'ri-palette-line'}></i>
                  {isActive ? 'Applied' : 'Apply Workspace'}
                </button>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
};

export default ThemeStorePage;

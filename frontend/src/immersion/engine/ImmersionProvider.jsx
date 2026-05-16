import { useCallback, useEffect, useMemo, useState } from 'react';
import { THEMES } from '../../config/themes';
import { ImmersionContext } from './ImmersionContext';

export const ImmersionProvider = ({ children }) => {
  const [themeId, setThemeId] = useState(() => {
    const savedTheme = localStorage.getItem('workspace_theme') || 'core';
    return THEMES[savedTheme] ? savedTheme : 'core';
  });

  const [performanceTier, setPerformanceTier] = useState(() => {
    return localStorage.getItem('performance_tier') || 'standard'; // minimal, standard, cinematic
  });

  const [threatLevel, setThreatLevel] = useState('safe'); // safe, elevated, critical

  const activeTheme = THEMES[themeId] || THEMES['core'];

  const [palette, setPalette] = useState({
    accent: '#06b6d4',
    accentStrong: '#0891b2',
    accentGlow: 'rgba(6, 182, 212, 0.1)',
    secondary: '#8b5cf6',
    surface: 'rgba(15, 23, 42, 0.86)',
    grid: 'rgba(255, 255, 255, 0.05)',
    text: '#f8fafc',
    textMuted: '#94a3b8',
    success: '#00ff9d',
    warning: '#ffbf00',
    danger: '#ff2a2a',
  });

  useEffect(() => {
    // Apply workspace environment theme
    document.documentElement.setAttribute('data-theme', themeId);
    
    // Apply cinematic typographies
    if (activeTheme.font) {
      document.documentElement.style.setProperty('--nv-font-body', activeTheme.font);
    }
    if (activeTheme.displayFont) {
      document.documentElement.style.setProperty('--nv-font-display', activeTheme.displayFont);
    }

    localStorage.setItem('workspace_theme', themeId);

    // Resolve CSS variables into real values for Canvas-based charts
    // We delay slightly to ensure CSS has applied
    const paletteTimer = window.setTimeout(() => {
      const styles = getComputedStyle(document.documentElement);
      setPalette({
        accent: styles.getPropertyValue('--primary').trim() || '#06b6d4',
        accentStrong: styles.getPropertyValue('--nv-accent-strong').trim() || '#0891b2',
        accentGlow: styles.getPropertyValue('--primary-glow').trim() || 'rgba(6, 182, 212, 0.1)',
        secondary: styles.getPropertyValue('--secondary').trim() || '#8b5cf6',
        surface: styles.getPropertyValue('--bg-card').trim() || 'rgba(15, 23, 42, 0.86)',
        grid: styles.getPropertyValue('--glass-border').trim() || 'rgba(255,255,255,0.05)',
        text: styles.getPropertyValue('--text-main').trim() || '#f8fafc',
        textMuted: styles.getPropertyValue('--text-muted').trim() || '#94a3b8',
        success: styles.getPropertyValue('--success').trim() || '#00ff9d',
        warning: styles.getPropertyValue('--warning').trim() || '#ffbf00',
        danger: styles.getPropertyValue('--danger').trim() || '#ff2a2a',
      });
    }, 50);

    return () => window.clearTimeout(paletteTimer);
  }, [themeId, activeTheme]);

  useEffect(() => {
    localStorage.setItem('performance_tier', performanceTier);
  }, [performanceTier]);

  const changeTheme = useCallback((newThemeId) => {
    if (THEMES[newThemeId]) {
      setThemeId(newThemeId);
    }
  }, []);

  const themesList = useMemo(() => Object.values(THEMES), []);

  const value = useMemo(() => ({
    themeId,
    activeTheme,
    performanceTier,
    setPerformanceTier,
    threatLevel,
    setThreatLevel,
    changeTheme,
    themesList,
    palette
  }), [activeTheme, changeTheme, palette, performanceTier, themeId, themesList, threatLevel]);

  return <ImmersionContext.Provider value={value}>{children}</ImmersionContext.Provider>;
};

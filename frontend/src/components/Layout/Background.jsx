import { useImmersion } from '../../immersion/engine/useImmersion';
import DeepSpace from '../../immersion/renderers/DeepSpace';
import SakuraParticles from '../../immersion/renderers/SakuraParticles';
import CyberGrid from '../../immersion/renderers/CyberGrid';
import Scanlines from '../../immersion/overlays/Scanlines';
import ThreatStrobe from '../../immersion/overlays/ThreatStrobe';
import Vignette from '../../immersion/overlays/Vignette';

const Background = () => {
  const { activeTheme, threatLevel } = useImmersion();
  const effects = activeTheme?.effects || {};

  return (
    <div
      className="ambient-background"
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: -1, // Render behind everything else
        backgroundColor: 'var(--bg-dark)',
      }}
    >
      {/* Base Theme Glows */}
      <div className="ambient-background__glow ambient-background__glow--cyan" style={{ opacity: effects.glowIntensity || 0.15 }}></div>
      <div className="ambient-background__glow ambient-background__glow--violet" style={{ opacity: (effects.glowIntensity || 0.15) * 0.8 }}></div>
      <div className="ambient-background__glow ambient-background__glow--blue" style={{ opacity: effects.glowIntensity || 0.15 }}></div>
      
      {/* Renderers */}
      {effects.particles && <DeepSpace />}
      {effects.sakura && <SakuraParticles />}
      {effects.grid && <CyberGrid />}

      {/* Atmospheric Overlays */}
      {effects.scanlines && <Scanlines />}

      {/* Threat Reactive Overlays */}
      {threatLevel === 'elevated' && <Vignette />}
      {threatLevel === 'critical' && <ThreatStrobe />}
    </div>
  );
};

export default Background;

import { useEffect, useRef } from 'react';
import { useImmersion } from '../../immersion/engine/useImmersion';
import DeepSpace from '../../immersion/renderers/DeepSpace';
import SakuraParticles from '../../immersion/renderers/SakuraParticles';
import CyberGrid from '../../immersion/renderers/CyberGrid';
import Scanlines from '../../immersion/overlays/Scanlines';
import ThreatStrobe from '../../immersion/overlays/ThreatStrobe';
import Vignette from '../../immersion/overlays/Vignette';

const TokyoSkyline = () => (
  <div
    className="tokyo-skyline"
    style={{
      position: 'absolute',
      bottom: 0,
      left: 0,
      right: 0,
      height: '32vh',
      opacity: 0.04,
      pointerEvents: 'none',
      zIndex: 2,
      backgroundImage: `url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1000 300' preserveAspectRatio='none'><path d='M0,300 L0,200 L30,200 L30,240 L60,240 L60,180 L90,180 L90,230 L120,230 L120,150 L150,150 L150,220 L180,220 L180,100 L210,100 L210,250 L240,250 L240,190 L270,190 L270,230 L300,230 L300,120 L330,120 L330,220 L360,220 L360,80 L380,80 L380,50 L390,50 L390,80 L410,80 L410,250 L440,250 L440,160 L470,160 L470,210 L500,210 L500,110 L530,110 L530,220 L560,220 L560,140 L590,140 L590,240 L620,240 L620,90 L650,90 L650,250 L680,250 L680,180 L710,180 L710,210 L740,210 L740,130 L770,130 L770,230 L800,230 L800,70 L820,70 L820,30 L830,30 L830,70 L850,70 L850,250 L880,250 L880,150 L910,150 L910,210 L940,210 L940,120 L970,120 L970,240 L1000,240 L1000,300 Z' fill='%23ff007f'/></svg>")`,
      backgroundSize: 'cover',
      backgroundPosition: 'bottom',
    }}
  />
);

const DigitalRain = () => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ'.split('');
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize) + 1;
    const drops = Array(columns).fill(1);

    const draw = () => {
      ctx.fillStyle = 'rgba(9, 2, 18, 0.06)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.font = `${fontSize}px monospace`;

      for (let i = 0; i < drops.length; i++) {
        ctx.fillStyle = i % 3 === 0 ? '#00f0ff' : '#ff007f';

        const char = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillText(char, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.985) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    };

    const interval = setInterval(draw, 33);

    return () => {
      clearInterval(interval);
      window.removeEventListener('resize', resizeCanvas);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        inset: 0,
        opacity: 0.1,
        pointerEvents: 'none',
        zIndex: 1,
      }}
    />
  );
};

const Background = () => {
  const { activeTheme, threatLevel, ambientEffectsEnabled } = useImmersion();
  const effects = activeTheme?.effects || {};

  return (
    <div
      className="ambient-background"
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        backgroundColor: 'var(--bg-dark)',
      }}
    >
      {/* Base Theme Glows */}
      <div className="ambient-background__glow ambient-background__glow--cyan" style={{ opacity: ambientEffectsEnabled ? (effects.glowIntensity || 0.15) : 0 }}></div>
      <div className="ambient-background__glow ambient-background__glow--violet" style={{ opacity: ambientEffectsEnabled ? ((effects.glowIntensity || 0.15) * 0.8) : 0 }}></div>
      <div className="ambient-background__glow ambient-background__glow--blue" style={{ opacity: ambientEffectsEnabled ? (effects.glowIntensity || 0.15) : 0 }}></div>
      
      {/* Renderers */}
      {ambientEffectsEnabled && effects.particles && <DeepSpace />}
      {ambientEffectsEnabled && effects.sakura && <SakuraParticles />}
      {ambientEffectsEnabled && effects.grid && <CyberGrid />}

      {/* Cyberpunk Tokyo overlays */}
      {ambientEffectsEnabled && activeTheme?.id === 'cyberpunk-tokyo' && <DigitalRain />}
      {ambientEffectsEnabled && activeTheme?.id === 'cyberpunk-tokyo' && <TokyoSkyline />}

      {/* Atmospheric Overlays */}
      {ambientEffectsEnabled && effects.scanlines && <Scanlines />}

      {/* Threat Reactive Overlays */}
      {threatLevel === 'elevated' && <Vignette />}
      {threatLevel === 'critical' && <ThreatStrobe />}
    </div>
  );
};

export default Background;

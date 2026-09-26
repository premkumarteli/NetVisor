import React, { useEffect, useRef } from 'react';

export const SpiralBackground = () => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
      renderSpiral();
    };

    window.addEventListener('resize', handleResize);

    // Pre-generate stable particles for the logarithmic spiral
    const particleCount = 1400;
    const particles = [];

    // Spiral parameters: 2 main spiral arms with star clusters and interstellar dust
    for (let i = 0; i < particleCount; i++) {
      const arm = i % 2 === 0 ? 0 : Math.PI;
      // Distance from center with logarithmic distribution
      const distRatio = Math.pow(Math.random(), 1.6);
      const r = 20 + distRatio * Math.min(width, 1200) * 0.48;
      
      // Logarithmic spiral angle + natural dispersion
      const theta = arm + Math.log(r / 20) * 2.8 + (Math.random() - 0.5) * (0.35 + distRatio * 0.45);
      
      const size = Math.random() < 0.08 ? Math.random() * 2.2 + 1.2 : Math.random() * 1.2 + 0.4;
      const alpha = Math.random() * 0.6 + 0.2;
      
      // Color variety: pure white, blue-white, icy cyan, faint warm star
      const colorType = Math.random();
      let color = '255, 255, 255';
      if (colorType < 0.4) {
        color = '210, 230, 255'; // icy blue-white
      } else if (colorType < 0.6) {
        color = '160, 205, 255'; // soft azure
      } else if (colorType < 0.75) {
        color = '255, 240, 220'; // warm core star
      }

      particles.push({ r, theta, size, alpha, color, pulseSpeed: 0.005 + Math.random() * 0.01, pulseOffset: Math.random() * Math.PI * 2 });
    }

    // Static ambient stars across the background
    const ambientStars = [];
    for (let i = 0; i < 220; i++) {
      ambientStars.push({
        x: Math.random() * width,
        y: Math.random() * height,
        size: Math.random() * 1.1 + 0.3,
        alpha: Math.random() * 0.4 + 0.1,
      });
    }

    let time = 0;

    const renderSpiral = () => {
      ctx.clearRect(0, 0, width, height);

      // Spiral center: horizontal center, positioned slightly above dashboard center (~38% of screen height)
      const cx = width * 0.62;
      const cy = height * 0.28;

      // 1. Ambient deep core glow
      const coreGradient = ctx.createRadialGradient(cx, cy, 0, cx, cy, Math.min(width, height) * 0.45);
      coreGradient.addColorStop(0, 'rgba(210, 230, 255, 0.18)');
      coreGradient.addColorStop(0.15, 'rgba(120, 170, 255, 0.12)');
      coreGradient.addColorStop(0.35, 'rgba(60, 100, 200, 0.06)');
      coreGradient.addColorStop(0.7, 'rgba(20, 40, 90, 0.02)');
      coreGradient.addColorStop(1, 'rgba(5, 7, 14, 0)');
      ctx.fillStyle = coreGradient;
      ctx.fillRect(0, 0, width, height);

      // 2. Faint ambient background stars
      ctx.fillStyle = '#FFFFFF';
      ambientStars.forEach((star) => {
        ctx.globalAlpha = star.alpha;
        ctx.beginPath();
        ctx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
        ctx.fill();
      });

      // 3. Draw Spiral Arms & Particles
      particles.forEach((p) => {
        const currentTheta = p.theta + time * 0.0003;
        const x = cx + p.r * Math.cos(currentTheta);
        const y = cy + p.r * 0.65 * Math.sin(currentTheta); // Elliptical perspective tilt

        const pulse = 0.8 + 0.2 * Math.sin(time * p.pulseSpeed + p.pulseOffset);
        const finalAlpha = p.alpha * pulse * 0.75;

        ctx.globalAlpha = finalAlpha;
        ctx.fillStyle = `rgb(${p.color})`;
        ctx.beginPath();
        ctx.arc(x, y, p.size, 0, Math.PI * 2);
        ctx.fill();

        // Extra soft glow for brighter cluster stars
        if (p.size > 1.8) {
          ctx.globalAlpha = finalAlpha * 0.3;
          ctx.beginPath();
          ctx.arc(x, y, p.size * 3.5, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // 4. Bright central galactic nucleus / observatory anchor
      const nucleus = ctx.createRadialGradient(cx, cy, 0, cx, cy, 32);
      nucleus.addColorStop(0, 'rgba(255, 255, 255, 0.45)');
      nucleus.addColorStop(0.3, 'rgba(210, 235, 255, 0.25)');
      nucleus.addColorStop(0.8, 'rgba(100, 160, 255, 0.08)');
      nucleus.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = nucleus;
      ctx.beginPath();
      ctx.arc(cx, cy, 40, 0, Math.PI * 2);
      ctx.fill();

      ctx.globalAlpha = 1;
    };

    let lastTime = 0;
    const animate = (timestamp) => {
      // Limit updates to ~30fps for minimal CPU impact
      if (timestamp - lastTime > 32) {
        time++;
        renderSpiral();
        lastTime = timestamp;
      }
      animationFrameId = requestAnimationFrame(animate);
    };

    renderSpiral();
    animationFrameId = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden bg-[#05070E]">
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full opacity-60"
        style={{ filter: 'blur(0.5px)' }}
      />
    </div>
  );
};

export default SpiralBackground;

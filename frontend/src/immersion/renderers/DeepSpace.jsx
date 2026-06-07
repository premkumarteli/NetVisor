import { useEffect, useRef } from 'react';
import { useImmersion } from '../engine/useImmersion';

const getGalaxyColors = (themeId) => {
  switch (themeId) {
    case 'cyberpunk-tokyo':
      return {
        core: '255, 0, 127', // pink/magenta
        arms: ['0, 240, 255', '139, 92, 246'], // cyan, violet
        stars: ['#ffffff', '#00f0ff', '#ff007f']
      };
    case 'matrix-terminal':
    case 'tactical-military':
      return {
        core: '0, 255, 65', // green
        arms: ['0, 109, 22', '0, 217, 54'], // greens
        stars: ['#ffffff', '#9cffad', '#00ff41']
      };
    case 'mecha-hud':
      return {
        core: '255, 69, 0', // orange/red
        arms: ['255, 215, 0', '255, 0, 0'], // gold, red
        stars: ['#ffffff', '#ffd700', '#ff4500']
      };
    case 'anime-neon':
      return {
        core: '180, 80, 255', // purple
        arms: ['255, 107, 203', '77, 238, 234'], // pink, cyan
        stars: ['#ffffff', '#ff6bcb', '#4deeea']
      };
    case 'space-station':
      return {
        core: '255, 140, 0', // orange
        arms: ['65, 105, 225', '255, 255, 255'], // royal blue, white
        stars: ['#ffffff', '#ff8c00', '#4169e1']
      };
    case 'retro-hacker':
      return {
        core: '255, 176, 0', // amber
        arms: ['255, 140, 0', '204, 136, 0'], // orange, dark amber
        stars: ['#ffb000', '#ff8c00', '#ffffff']
      };
    case 'ai-core':
      return {
        core: '0, 102, 255', // clean blue
        arms: ['0, 204, 255', '96, 111, 123'], // cyan, slate
        stars: ['#51657c', '#0066ff', '#ffffff']
      };
    case 'core':
    default:
      return {
        core: '84, 200, 232', // cyan
        arms: ['139, 92, 246', '45, 212, 191'], // violet, teal
        stars: ['#ffffff', '#54c8e8', '#8b5cf6']
      };
  }
};

const DeepSpace = () => {
  const canvasRef = useRef(null);
  const { themeId, performanceTier } = useImmersion();

  useEffect(() => {
    if (performanceTier === 'minimal') return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    let width, height;
    let stars = [];
    let nebulaClouds = [];
    let animationFrameId;
    let lastFrameAt = 0;
    const frameInterval = performanceTier === 'cinematic' ? 1000 / 60 : 1000 / 24;

    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", resize);
    resize();

    const colors = getGalaxyColors(themeId);
    const tiltFactor = 0.38; // perspective inclination
    const galaxyAngle = -0.45; // rotate the galaxy slightly for an organic angle
    const cosG = Math.cos(galaxyAngle);
    const sinG = Math.sin(galaxyAngle);

    class Star {
      constructor() {
        this.reset();
        // Randomize initial positions
        this.angleOffset = Math.random() * Math.PI * 2;
      }

      reset() {
        const maxRadius = Math.min(width, height) * 0.48;
        this.distance = Math.pow(Math.random(), 1.7) * maxRadius;
        
        // 85% of stars reside in spiral arms, 15% are scattered background/halo stars
        this.isArmStar = Math.random() < 0.85;
        this.arm = Math.random() < 0.5 ? 0 : 1;
        
        const spiralTightness = 5.6 / maxRadius;
        const dispersion = 0.22 + (1.0 - this.distance / maxRadius) * 0.65;
        
        if (this.isArmStar) {
          this.angleOffset = (this.arm * Math.PI) + (this.distance * spiralTightness) + (Math.random() - 0.5) * dispersion;
        } else {
          this.angleOffset = Math.random() * Math.PI * 2;
        }

        this.size = Math.random() * 1.5 + 0.35;
        // Core stars are denser and brighter
        if (this.distance < maxRadius * 0.15) {
          this.size += Math.random() * 0.7;
        }
        
        this.opacity = Math.random() * 0.55 + 0.2;
        this.speedMultiplier = 0.95 + Math.random() * 0.1;
        this.color = colors.stars[Math.floor(Math.random() * colors.stars.length)];
      }

      update() {
        // Differential galactic rotation: inner stars orbit faster
        const orbitalSpeed = 0.0006 + (20 / (this.distance + 80)) * 0.0035;
        this.angleOffset += orbitalSpeed * this.speedMultiplier;
      }

      draw(cx, cy) {
        const planeX = Math.cos(this.angleOffset) * this.distance;
        const planeY = Math.sin(this.angleOffset) * this.distance * tiltFactor;

        // Apply galaxy tilt and rotation
        const x = cx + (planeX * cosG - planeY * sinG);
        const y = cy + (planeX * sinG + planeY * cosG);

        ctx.fillStyle = this.color;
        ctx.beginPath();
        ctx.arc(x, y, this.size, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    class NebulaCloud {
      constructor() {
        this.reset();
        this.angleOffset = Math.random() * Math.PI * 2;
      }

      reset() {
        const maxRadius = Math.min(width, height) * 0.45;
        this.distance = Math.pow(Math.random(), 1.5) * maxRadius;
        this.arm = Math.random() < 0.5 ? 0 : 1;
        
        const spiralTightness = 5.6 / maxRadius;
        const dispersion = 0.45 + (1.0 - this.distance / maxRadius) * 0.55;
        
        this.angleOffset = (this.arm * Math.PI) + (this.distance * spiralTightness) + (Math.random() - 0.5) * dispersion;
        
        this.size = Math.random() * 40 + 20;
        if (this.distance < maxRadius * 0.22) {
          this.size += 15; // Larger core gas cloud size
        }
        
        this.opacity = Math.random() * 0.02 + 0.008;
        this.speedMultiplier = 0.98 + Math.random() * 0.04;
        
        if (this.distance < maxRadius * 0.2) {
          this.color = colors.core;
        } else {
          this.color = colors.arms[Math.floor(Math.random() * colors.arms.length)];
        }
      }

      update() {
        const orbitalSpeed = 0.0006 + (20 / (this.distance + 80)) * 0.0035;
        this.angleOffset += orbitalSpeed * this.speedMultiplier;
      }

      draw(cx, cy) {
        const planeX = Math.cos(this.angleOffset) * this.distance;
        const planeY = Math.sin(this.angleOffset) * this.distance * tiltFactor;

        const x = cx + (planeX * cosG - planeY * sinG);
        const y = cy + (planeX * sinG + planeY * cosG);

        const gradient = ctx.createRadialGradient(x, y, 0, x, y, this.size);
        gradient.addColorStop(0, `rgba(${this.color}, ${this.opacity})`);
        gradient.addColorStop(0.5, `rgba(${this.color}, ${this.opacity * 0.4})`);
        gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(x, y, this.size, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    const init = () => {
      stars = [];
      nebulaClouds = [];

      // Scale count with performance tier
      let starCount = 120;
      let cloudCount = 8;

      if (performanceTier === 'cinematic') {
        starCount = 450;
        cloudCount = 40;
      }

      for (let i = 0; i < starCount; i++) {
        stars.push(new Star());
      }
      for (let i = 0; i < cloudCount; i++) {
        nebulaClouds.push(new NebulaCloud());
      }
    };

    const drawCoreGlow = (cx, cy, maxRadius) => {
      const coreSize = maxRadius * 0.22;
      const gradient = ctx.createRadialGradient(cx, cy, 0, cx, cy, coreSize);
      gradient.addColorStop(0, `rgba(${colors.core}, 0.24)`);
      gradient.addColorStop(0.4, `rgba(${colors.core}, 0.08)`);
      gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(galaxyAngle);
      ctx.scale(1, tiltFactor);
      
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(0, 0, coreSize, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    };

    init();

    const animate = (timestamp = 0) => {
      if (document.hidden) {
        animationFrameId = requestAnimationFrame(animate);
        return;
      }

      if (timestamp - lastFrameAt < frameInterval) {
        animationFrameId = requestAnimationFrame(animate);
        return;
      }
      lastFrameAt = timestamp;

      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;
      const maxRadius = Math.min(width, height) * 0.48;

      // 1. Draw Nebula gas clouds first (background)
      nebulaClouds.forEach((cloud) => {
        cloud.update();
        cloud.draw(cx, cy);
      });

      // 2. Draw Galactic core glow
      drawCoreGlow(cx, cy, maxRadius);

      // 3. Draw Stars on top
      stars.forEach((star) => {
        star.update();
        star.draw(cx, cy);
      });

      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [themeId, performanceTier]);

  if (performanceTier === 'minimal') return null;

  return (
    <canvas 
      ref={canvasRef} 
      className="immersion-renderer"
      style={{ 
        position: 'absolute', 
        top: 0, 
        left: 0, 
        width: '100%', 
        height: '100%', 
        pointerEvents: 'none',
        zIndex: 2
      }} 
    />
  );
};

export default DeepSpace;

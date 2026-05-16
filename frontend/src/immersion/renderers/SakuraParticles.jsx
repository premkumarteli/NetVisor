import { useEffect, useRef } from 'react';
import { useImmersion } from '../engine/useImmersion';

const SakuraParticles = () => {
  const canvasRef = useRef(null);
  const { performanceTier } = useImmersion();

  useEffect(() => {
    if (performanceTier === 'minimal') return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    let width, height;
    let petals = [];
    let animationFrameId;

    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    class Petal {
      constructor() {
        this.reset();
        this.y = Math.random() * height;
      }
      reset() {
        this.x = Math.random() * width;
        this.y = -10;
        this.z = Math.random() * 2 + 0.5;
        this.size = Math.random() * 2 + 1;
        this.opacity = Math.random() * 0.6 + 0.2;
        this.vx = (Math.random() - 0.5) * 1;
      }
      update() {
        this.y += this.z * 0.3;
        this.x += this.vx;
        if (this.y > height || this.x < 0 || this.x > width) this.reset();
      }
      draw() {
        ctx.fillStyle = `rgba(255, 107, 107, ${this.opacity})`;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    const init = () => {
      petals = [];
      const particleCount = performanceTier === 'cinematic' ? 150 : 75;
      for (let i = 0; i < particleCount; i++) petals.push(new Petal());
    };

    const animate = () => {
      ctx.clearRect(0, 0, width, height);

      petals.forEach((p) => {
        p.update();
        p.draw();
      });

      animationFrameId = requestAnimationFrame(animate);
    };

    window.addEventListener("resize", resize);
    resize();
    init();
    animate();

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [performanceTier]);

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

export default SakuraParticles;

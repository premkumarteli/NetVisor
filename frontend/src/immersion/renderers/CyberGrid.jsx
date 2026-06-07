import { useImmersion } from '../engine/useImmersion';

const CyberGrid = () => {
  const { performanceTier } = useImmersion();

  if (performanceTier === 'minimal') return null;

  return (
    <div 
      className="immersion-renderer cyber-grid"
      style={{ 
        position: 'absolute', 
        inset: 0, 
        backgroundImage: 'linear-gradient(var(--border-glow) 1px, transparent 1px), linear-gradient(90deg, var(--border-glow) 1px, transparent 1px)', 
        backgroundSize: '40px 40px', 
        opacity: 0.2, 
        transform: 'perspective(500px) rotateX(60deg) translateY(-100px) translateZ(-200px)', 
        pointerEvents: 'none', 
        zIndex: 1 
      }}
    />
  );
};

export default CyberGrid;

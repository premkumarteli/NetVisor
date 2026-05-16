const ThreatStrobe = () => {
  return (
    <div 
      className="immersion-overlay threat-strobe"
      style={{ 
        position: 'absolute', 
        inset: 0, 
        background: 'radial-gradient(circle at center, transparent 30%, rgba(255, 0, 0, 0.1) 100%)',
        boxShadow: 'inset 0 0 200px rgba(255, 0, 0, 0.3)', 
        animation: 'pulse-danger 2s infinite alternate',
        pointerEvents: 'none', 
        zIndex: 20 
      }}
    >
      <style>{`
        @keyframes pulse-danger {
          0% { opacity: 0.5; }
          100% { opacity: 1; }
        }
      `}</style>
    </div>
  );
};

export default ThreatStrobe;

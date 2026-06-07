const Scanlines = () => {
  return (
    <div 
      className="immersion-overlay scanlines"
      style={{ 
        position: 'absolute', 
        inset: 0, 
        background: 'linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06))', 
        backgroundSize: '100% 2px, 3px 100%', 
        pointerEvents: 'none', 
        zIndex: 10 
      }}
    />
  );
};

export default Scanlines;

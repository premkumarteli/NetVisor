const Vignette = () => {
  return (
    <div 
      className="immersion-overlay vignette"
      style={{ 
        position: 'absolute', 
        inset: 0, 
        boxShadow: 'inset 0 0 150px rgba(255, 165, 0, 0.15)', 
        pointerEvents: 'none', 
        zIndex: 20 
      }}
    />
  );
};

export default Vignette;

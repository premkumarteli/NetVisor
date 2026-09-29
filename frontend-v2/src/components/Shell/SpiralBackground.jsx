import React, { useEffect, useRef, useState } from 'react';

export const SpiralBackground = () => {
  const videoRef = useRef(null);
  const [videoLoaded, setVideoLoaded] = useState(false);

  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.playbackRate = 0.85; // Slightly slower cinematic pace
    }
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden bg-[#05070E]">
      {/* 1. HTML5 Ambient Background Video */}
      <video
        ref={videoRef}
        autoPlay
        loop
        muted
        playsInline
        onLoadedData={() => setVideoLoaded(true)}
        className={`absolute inset-0 w-full h-full object-cover transition-opacity duration-1000 ${
          videoLoaded ? 'opacity-40' : 'opacity-0'
        }`}
        style={{
          filter: 'saturate(130%) contrast(110%) brightness(85%)',
        }}
      >
        <source src="/bg-video.mp4" type="video/mp4" />
      </video>

      {/* 2. Observatory Cosmic Vignette & Color Grading Overlay */}
      <div
        className="absolute inset-0"
        style={{
          background:
            'radial-gradient(ellipse at 60% 30%, rgba(16, 24, 48, 0.45) 0%, rgba(5, 7, 14, 0.75) 55%, rgba(3, 4, 8, 0.92) 100%)',
        }}
      />

      {/* 3. Subtle grid scanline texture for high-tech HUD feeling */}
      <div
        className="absolute inset-0 opacity-[0.035]"
        style={{
          backgroundImage:
            'linear-gradient(to right, rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.1) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />
    </div>
  );
};

export default SpiralBackground;


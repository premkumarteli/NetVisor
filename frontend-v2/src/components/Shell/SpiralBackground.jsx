import React, { useEffect, useRef, useState } from 'react';

export const SpiralBackground = () => {
  const videoRef = useRef(null);
  const [videoLoaded, setVideoLoaded] = useState(false);

  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.playbackRate = 1.0; // Original natural playback rate
    }
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden bg-[#05070E]">
      {/* 1. HTML5 Ambient Background Video - Original Brightness & Full Clarity */}
      <video
        ref={videoRef}
        autoPlay
        loop
        muted
        playsInline
        onLoadedData={() => setVideoLoaded(true)}
        className={`absolute inset-0 w-full h-full object-cover transition-opacity duration-700 ${
          videoLoaded ? 'opacity-100' : 'opacity-0'
        }`}
        style={{
          filter: 'brightness(100%) contrast(100%) saturate(100%)',
        }}
      >
        <source src="/bg-video.mp4" type="video/mp4" />
      </video>

      {/* 2. Delicate ambient contrast overlay to preserve UI card readability */}
      <div
        className="absolute inset-0"
        style={{
          background:
            'radial-gradient(ellipse at 50% 40%, rgba(5, 7, 14, 0.15) 0%, rgba(5, 7, 14, 0.45) 80%, rgba(3, 4, 8, 0.7) 100%)',
        }}
      />

      {/* 3. Micro scanline grid for observatory HUD depth */}
      <div
        className="absolute inset-0 opacity-[0.02]"
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

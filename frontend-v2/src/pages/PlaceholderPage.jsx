import React from 'react';

export const PlaceholderPage = ({ title, description }) => {
  return (
    <div className="glass-card p-8 flex flex-col items-center justify-center text-center min-h-[400px]">
      <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-2xl text-[#9AA3B8] mb-3">
        <i className="ri-time-line"></i>
      </div>
      <h2 className="text-xl font-bold text-[#F1F3F9] mb-1">{title}</h2>
      <p className="text-xs text-[#9AA3B8] max-w-md">{description}</p>
    </div>
  );
};

export default PlaceholderPage;

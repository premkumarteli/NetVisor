import React, { useEffect } from 'react';

export const SidePanel = ({
  open,
  title,
  description,
  onClose,
  children,
  footer,
  width = 'max-w-xl',
}) => {
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === 'Escape' && open) {
        onClose?.();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer Panel */}
      <div
        className={`relative z-10 w-full ${width} h-full glass-card rounded-none border-y-0 border-r-0 border-l border-white/10 flex flex-col shadow-2xl transition-transform duration-300 ease-out`}
        style={{
          background: 'rgba(17, 20, 34, 0.88)',
          backdropFilter: 'blur(28px) saturate(160%)',
          WebkitBackdropFilter: 'blur(28px) saturate(160%)',
        }}
      >
        {/* Header */}
        <div className="p-6 border-b border-white/10 flex items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-bold text-[#F1F3F9] tracking-tight">{title}</h3>
            {description && (
              <p className="text-xs text-[#9AA3B8] mt-1 leading-relaxed">{description}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-8 h-8 rounded-lg flex items-center justify-center text-[#9AA3B8] hover:text-white hover:bg-white/5 transition-colors"
            aria-label="Close panel"
          >
            <i className="ri-close-line text-xl"></i>
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {children}
        </div>

        {/* Footer */}
        {footer && (
          <div className="p-4 px-6 border-t border-white/10 bg-black/20 flex items-center justify-end gap-3">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

export default SidePanel;

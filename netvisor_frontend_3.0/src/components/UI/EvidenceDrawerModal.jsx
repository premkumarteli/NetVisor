import React from 'react';

export const EvidenceDrawerModal = ({ isOpen, onClose, title, data }) => {
  if (!isOpen || !data) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm transition-opacity duration-200">
      <div className="w-full max-w-xl h-full glass-panel border-l border-cyan-500/20 bg-slate-950/95 p-6 flex flex-col shadow-2xl overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <span className="text-xs uppercase font-mono-code text-cyan-400 font-semibold tracking-wider">Single Row Deep Evidence</span>
            <h3 className="text-lg font-bold text-slate-100">{title || "Item Evidence Inspection"}</h3>
          </div>
          <button 
            type="button" 
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800/80 text-slate-400 hover:text-slate-200 border border-slate-700/60 flex items-center justify-center text-lg"
          >
            <i className="ri-close-line"></i>
          </button>
        </div>

        {/* JSON Payload Inspection */}
        <div className="mt-6 flex-1 space-y-4">
          <div className="bg-slate-900/90 rounded-xl p-4 border border-slate-800 font-mono-code text-xs text-cyan-300 overflow-x-auto">
            <pre>{JSON.stringify(data, null, 2)}</pre>
          </div>

          <div className="glass-panel rounded-xl p-4 space-y-2">
            <h4 className="text-xs font-semibold uppercase text-slate-400">Analyst Actions</h4>
            <div className="flex items-center gap-2 flex-wrap pt-1">
              <button 
                type="button" 
                onClick={() => alert(`Single Row Action executed: Quarantined item ${data.id || data.hostname}`)}
                className="px-3 py-1.5 text-xs bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded-lg hover:bg-rose-500/30 flex items-center gap-1.5"
              >
                <i className="ri-shield-cross-line"></i>
                Quarantine Asset
              </button>
              <button 
                type="button" 
                onClick={() => alert(`Single Row Action executed: Flagged ${data.id || data.domain}`)}
                className="px-3 py-1.5 text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg hover:bg-amber-500/30 flex items-center gap-1.5"
              >
                <i className="ri-flag-line"></i>
                Flag Threat Intel
              </button>
              <button 
                type="button" 
                onClick={() => alert(`Copied JSON payload to clipboard!`)}
                className="px-3 py-1.5 text-xs bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 flex items-center gap-1.5"
              >
                <i className="ri-file-copy-line"></i>
                Copy Raw Payload
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

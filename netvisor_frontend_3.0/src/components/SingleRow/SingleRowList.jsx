import React from 'react';

export const SingleRowList = ({ children, emptyTitle = "No items found", emptyDescription = "There are no records matching your current filter criteria.", className = "" }) => {
  const childCount = React.Children.count(children);

  if (childCount === 0) {
    return (
      <div className="glass-panel rounded-2xl p-12 text-center flex flex-col items-center justify-center">
        <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center text-2xl mb-4">
          <i className="ri-inbox-archive-line"></i>
        </div>
        <h3 className="text-lg font-semibold text-slate-200">{emptyTitle}</h3>
        <p className="text-sm text-slate-400 max-w-md mt-1 font-mono-code">{emptyDescription}</p>
      </div>
    );
  }

  return (
    <div className={`space-y-3 ${className}`}>
      {children}
    </div>
  );
};

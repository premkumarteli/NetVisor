import React from 'react';

export const FilterBar = ({
  searchValue = '',
  onSearchChange,
  categories = [],
  activeCategory = 'ALL',
  onCategoryChange,
  placeholder = "Search items, IP addresses, domains..."
}) => {
  return (
    <div className="glass-panel rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-4 mb-6">
      {/* Search Input */}
      <div className="relative w-full md:w-80">
        <i className="ri-search-line absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 text-base"></i>
        <input
          type="text"
          value={searchValue}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder={placeholder}
          className="w-full pl-10 pr-4 py-2 text-xs md:text-sm bg-slate-900/90 border border-slate-700/80 rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono-code"
        />
        {searchValue && (
          <button 
            type="button" 
            onClick={() => onSearchChange('')} 
            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
          >
            <i className="ri-close-line"></i>
          </button>
        )}
      </div>

      {/* Category Pills */}
      {categories.length > 0 && (
        <div className="flex items-center gap-1.5 overflow-x-auto w-full md:w-auto pb-1 md:pb-0 scrollbar-none">
          {categories.map((cat) => {
            const isSelected = activeCategory === cat.key;
            return (
              <button
                key={cat.key}
                type="button"
                onClick={() => onCategoryChange(cat.key)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-xl whitespace-nowrap transition-all duration-150 border ${
                  isSelected
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm shadow-cyan-500/10'
                    : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-300'
                }`}
              >
                {cat.label} {cat.count !== undefined && <span className="ml-1 opacity-70">({cat.count})</span>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

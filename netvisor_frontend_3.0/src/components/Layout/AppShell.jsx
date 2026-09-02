import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';

export const AppShell = ({ children }) => {
  const location = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const navigation = [
    { name: 'Dashboard', path: '/', icon: 'ri-dashboard-3-line' },
    { name: 'Traffic Activity', path: '/activity', icon: 'ri-exchange-box-line' },
    { name: 'Devices', path: '/devices', icon: 'ri-macbook-line' },
    { name: 'Applications', path: '/applications', icon: 'ri-apps-2-line' },
    { name: 'Security Threats', path: '/threats', icon: 'ri-alarm-warning-line' },
    { name: 'DPI Web Inspection', path: '/dpi', icon: 'ri-global-line' },
    { name: 'System Logs', path: '/logs', icon: 'ri-terminal-box-line' },
    { name: 'Agents & Nodes', path: '/agents', icon: 'ri-cpu-line' },
    { name: 'VPN Tunnels', path: '/vpn', icon: 'ri-shield-keyhole-line' },
    { name: 'Users', path: '/users', icon: 'ri-user-settings-line' },
    { name: 'Settings', path: '/settings', icon: 'ri-settings-4-line' }
  ];

  return (
    <div className="min-h-screen flex bg-[#05070d] text-slate-100 relative">
      {/* Sidebar Navigation */}
      <aside className={`fixed inset-y-0 left-0 z-40 w-64 glass-panel border-r border-slate-800 bg-slate-950/90 flex flex-col transition-transform duration-200 lg:translate-x-0 ${mobileNavOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        {/* Brand Header */}
        <div className="p-5 flex items-center justify-between border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-black font-bold text-lg">
              <i className="ri-shield-flash-line"></i>
            </div>
            <div>
              <h1 className="font-bold text-base tracking-tight text-white flex items-center gap-1.5">
                NetVisor <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400 font-mono-code border border-cyan-500/30">3.0</span>
              </h1>
              <p className="text-[10px] text-slate-400 font-mono-code">Single-Row Functional UI</p>
            </div>
          </div>
          <button 
            type="button" 
            onClick={() => setMobileNavOpen(false)}
            className="lg:hidden text-slate-400 hover:text-white"
          >
            <i className="ri-close-line text-xl"></i>
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {navigation.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setMobileNavOpen(false)}
                className={`flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all duration-150 ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/10 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <i className={`${item.icon} text-base ${isActive ? 'text-cyan-400' : 'text-slate-400'}`}></i>
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* Bottom User / System Info */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-900/40">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center justify-center font-bold text-xs">
              AD
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold text-slate-200 truncate">admin (SOC Lead)</p>
              <p className="text-[10px] text-emerald-400 font-mono-code flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                DB Sample Data Mode
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Layout Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        {/* Top Header */}
        <header className="sticky top-0 z-30 h-16 glass-panel border-b border-slate-800/80 px-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button 
              type="button" 
              onClick={() => setMobileNavOpen(true)}
              className="lg:hidden text-slate-400 hover:text-white p-1"
            >
              <i className="ri-menu-line text-xl"></i>
            </button>
            <span className="text-xs font-mono-code text-slate-400 hidden sm:inline-block">
              NetVisor Frontend 3.0 &bull; Standalone UI Prototype &bull; Single Row Action Architecture
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span className="px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px] font-mono-code">
              Gateway: 192.168.137.1 [ONLINE]
            </span>
            <button 
              type="button" 
              onClick={() => alert("NetVisor 3.0 Sample DB Preview Mode Active!")}
              className="p-2 rounded-xl bg-slate-900 border border-slate-700/80 text-slate-300 hover:text-cyan-400 transition-colors text-sm"
              title="System Status"
            >
              <i className="ri-notification-3-line"></i>
            </button>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-4 md:p-6 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

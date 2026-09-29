import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import SpiralBackground from './SpiralBackground';

const TABS = [
  { id: 'dashboard', path: '/', label: 'Dashboard', icon: 'ri-home-5-line' },
  { id: 'devices', path: '/devices', label: 'Devices', icon: 'ri-macbook-line' },
  { id: 'agents', path: '/agents', label: 'Agents', icon: 'ri-box-3-line' },
  { id: 'threats', path: '/threats', label: 'Threats', icon: 'ri-shield-flash-line', badgeKey: 'threats' },
  { id: 'vpn', path: '/vpn', label: 'VPN', icon: 'ri-wifi-line' },
  { id: 'activity', path: '/activity', label: 'Activity', icon: 'ri-pulse-line' },
  { id: 'apps', path: '/apps', label: 'Apps', icon: 'ri-apps-2-line' },
  { id: 'settings', path: '/settings', label: 'Settings', icon: 'ri-settings-4-line' },
];

export const AppShell = ({
  children,
  socketStatus = 'connected',
  highThreatsCount = 0,
}) => {
  const location = useLocation();
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <div className="min-h-screen relative flex flex-col bg-[#05070E] text-[#F1F3F9] selection:bg-blue-500/20 selection:text-blue-200">
      {/* 1. Spiral Particle Observatory Background Layer */}
      <SpiralBackground />

      {/* 2. Topbar Navigation Header */}
      <header
        className="sticky top-0 z-40 w-full border-b border-white/[0.06]"
        style={{
          background: 'rgba(9, 12, 22, 0.75)',
          backdropFilter: 'blur(24px) saturate(180%)',
          WebkitBackdropFilter: 'blur(24px) saturate(180%)',
        }}
      >
        <div className="max-w-7xl w-full mx-auto px-6 h-14 flex items-center justify-between gap-6">
          {/* Brand Mark */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-xl bg-[#2563EB]/20 border border-[#3B82F6]/40 flex items-center justify-center text-[#60A5FA] shadow-[0_0_12px_rgba(59,130,246,0.25)]">
              <i className="ri-shield-keyhole-fill text-lg"></i>
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-tight text-[#FFFFFF] leading-tight">
                NetVisor
              </h1>
              <p className="text-[10px] text-[#9AA3B8] font-medium leading-none">
                Network Security Monitor
              </p>
            </div>
          </div>

          {/* Centered Global Search Input (Exact to reference mockup) */}
          <div className="flex-1 max-w-md hidden md:block">
            <div className="relative flex items-center">
              <i className="ri-search-line absolute left-3 text-[#5E6579] text-xs pointer-events-none"></i>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search devices, IPs, domains, users..."
                className="w-full h-8 pl-8 pr-10 rounded-lg bg-white/[0.04] hover:bg-white/[0.06] focus:bg-white/[0.08] border border-white/[0.08] focus:border-blue-500/50 text-xs text-[#F1F3F9] placeholder-[#5E6579] outline-none transition-all duration-150"
              />
              <span className="absolute right-2.5 px-1.5 py-0.5 rounded bg-white/[0.06] border border-white/[0.1] text-[9.5px] mono text-[#9AA3B8] pointer-events-none">
                ⌘ K
              </span>
            </div>
          </div>

          {/* Right Action Controls (Theme, Notifications, User Badge) */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Theme Toggle */}
            <button
              type="button"
              className="w-7 h-7 rounded-lg bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] flex items-center justify-center text-[#9AA3B8] hover:text-white transition-colors"
              title="Toggle theme"
            >
              <i className="ri-sun-line text-xs"></i>
            </button>

            {/* Notifications Bell with Unread Badge */}
            <button
              type="button"
              className="relative w-7 h-7 rounded-lg bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] flex items-center justify-center text-[#9AA3B8] hover:text-white transition-colors"
              title="System alerts"
            >
              <i className="ri-notification-3-line text-xs"></i>
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-[#EF4444] ring-2 ring-[#0B0F1A]" />
            </button>

            {/* User Profile Pill */}
            <div className="flex items-center gap-2 pl-1.5 py-0.5 pr-2.5 rounded-full bg-white/[0.03] border border-white/[0.06]">
              <div className="w-6 h-6 rounded-full bg-gradient-to-tr from-blue-500 to-indigo-500 flex items-center justify-center text-[10.5px] font-bold text-white shadow-sm">
                P
              </div>
              <div className="text-left hidden sm:block">
                <div className="text-xs font-semibold text-[#F1F3F9] leading-none">Premkumar</div>
                <div className="text-[9px] text-[#9AA3B8] leading-tight">Admin</div>
              </div>
              <i className="ri-arrow-down-s-line text-[10px] text-[#5E6579]"></i>
            </div>
          </div>
        </div>
      </header>

      {/* 3. Main Workspace Canvas */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 pt-5 pb-20">
        {children}
      </main>

      {/* 4. Floating Bottom Dock (Reference: Pill dock with soft glow) */}
      <div className="fixed bottom-3.5 left-1/2 -translate-x-1/2 z-40 pointer-events-none">
        <nav
          className="pointer-events-auto flex items-center gap-1 p-1 rounded-2xl border border-white/[0.09]"
          style={{
            background: 'rgba(11, 15, 27, 0.82)',
            backdropFilter: 'blur(28px) saturate(180%)',
            WebkitBackdropFilter: 'blur(28px) saturate(180%)',
            boxShadow: '0 15px 40px rgba(0, 0, 0, 0.6), 0 0 1px 1px rgba(255, 255, 255, 0.05)',
          }}
        >
          {TABS.map((tab) => {
            const isActive =
              tab.path === '/'
                ? location.pathname === '/' || location.pathname === '/dashboard'
                : location.pathname.startsWith(tab.path);

            const hasRoseBadge = tab.badgeKey === 'threats' && highThreatsCount > 0;

            return (
              <NavLink
                key={tab.id}
                to={tab.path}
                className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all duration-200 ${
                  isActive
                    ? 'bg-blue-500/15 text-[#60A5FA] border border-blue-500/30 shadow-[0_0_10px_rgba(59,130,246,0.18)]'
                    : 'text-[#9AA3B8] hover:text-[#F1F3F9] hover:bg-white/[0.03] border border-transparent'
                }`}
              >
                <div className="relative flex items-center justify-center">
                  <i className={`${tab.icon} text-sm`}></i>
                  {hasRoseBadge && (
                    <span className="absolute -top-1 -right-1 w-1.5 h-1.5 rounded-full bg-[#EF4444] ring-2 ring-[#0B0F1A] shadow-[0_0_6px_#EF4444]" />
                  )}
                </div>
                <span className="hidden sm:inline">{tab.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </div>
    </div>
  );
};

export default AppShell;

import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import SpiralBackground from './SpiralBackground';

const TABS = [
  { id: 'dashboard', path: '/', label: 'Dashboard', icon: 'ri-home-4-line' },
  { id: 'devices', path: '/devices', label: 'Devices', icon: 'ri-macbook-line' },
  { id: 'agents', path: '/agents', label: 'Agents', icon: 'ri-box-3-line' },
  { id: 'threats', path: '/threats', label: 'Threats', icon: 'ri-shield-flash-line', badgeKey: 'threats' },
  { id: 'vpn', path: '/vpn', label: 'VPN', icon: 'ri-wifi-line' },
  { id: 'activity', path: '/activity', label: 'Activity', icon: 'ri-pulse-line' },
  { id: 'logs', path: '/activity?view=search', label: 'Logs', icon: 'ri-file-list-2-line' },
  { id: 'users', path: '/settings?tab=users', label: 'Users', icon: 'ri-group-line' },
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
      {/* 1. Ambient Observatory Cosmic Video Background */}
      <SpiralBackground />

      {/* 2. Topbar Navigation Header */}
      <header
        className="sticky top-0 z-40 w-full border-b border-white/[0.08]"
        style={{
          background: 'linear-gradient(180deg, rgba(255, 255, 255, 0.05) 0%, rgba(9, 12, 22, 0.7) 100%), rgba(9, 12, 22, 0.72)',
          backdropFilter: 'blur(28px) saturate(190%)',
          WebkitBackdropFilter: 'blur(28px) saturate(190%)',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
        }}
      >
        <div className="max-w-[1260px] w-full mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">
          {/* Brand Mark */}
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="w-8 h-8 rounded-xl bg-blue-600/20 border border-blue-400/40 flex items-center justify-center text-[#60A5FA] shadow-[0_0_16px_rgba(59,130,246,0.3)]">
              <i className="ri-shield-keyhole-fill text-lg"></i>
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-tight text-[#FFFFFF] leading-tight">
                NetVisor
              </h1>
              <p className="text-[9.5px] text-[#9AA3B8] font-medium leading-none">
                Network Security Monitor
              </p>
            </div>
          </div>

          {/* Centered Global Search Input */}
          <div className="flex-1 max-w-md hidden md:block">
            <div className="relative flex items-center">
              <i className="ri-search-line absolute left-3.5 text-[#5E6579] text-xs pointer-events-none"></i>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search devices, IPs, domains, users..."
                className="w-full h-8.5 pl-9 pr-11 rounded-xl bg-white/[0.04] hover:bg-white/[0.07] focus:bg-white/[0.09] border border-white/[0.09] focus:border-blue-500/50 text-xs text-[#F1F3F9] placeholder-[#5E6579] outline-none transition-all duration-150"
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
              className="w-8 h-8 rounded-xl bg-white/[0.03] hover:bg-white/[0.08] border border-white/[0.08] flex items-center justify-center text-[#9AA3B8] hover:text-white transition-colors cursor-pointer"
              title="Toggle theme"
            >
              <i className="ri-sun-line text-sm"></i>
            </button>

            {/* Notifications Bell with Unread Badge */}
            <button
              type="button"
              className="relative w-8 h-8 rounded-xl bg-white/[0.03] hover:bg-white/[0.08] border border-white/[0.08] flex items-center justify-center text-[#9AA3B8] hover:text-white transition-colors cursor-pointer"
              title="System alerts"
            >
              <i className="ri-notification-3-line text-sm"></i>
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-[#EF4444] ring-2 ring-[#0B0F1A] shadow-[0_0_6px_#EF4444]" />
            </button>

            {/* User Profile Pill */}
            <div className="flex items-center gap-2.5 pl-1.5 py-1 pr-3 rounded-full bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.07] transition-colors cursor-pointer">
              <div className="w-6 h-6 rounded-full bg-gradient-to-tr from-blue-500 to-indigo-500 flex items-center justify-center text-[11px] font-bold text-white shadow-sm">
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

      {/* 3. Main Workspace Canvas (+20% width: max-w-[1260px]) */}
      <main className="relative z-10 flex-1 max-w-[1260px] w-full mx-auto px-4 sm:px-6 pt-5 pb-24">
        {children}
      </main>

      {/* 4. Floating Bottom Dock Bar */}
      <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-40 pointer-events-none">
        <nav
          className="pointer-events-auto flex items-center gap-1.5 sm:gap-2 px-3 py-1.5 rounded-2xl glass-chrome"
        >
          {TABS.map((tab) => {
            const isTabActive =
              tab.path === '/'
                ? location.pathname === '/' || location.pathname === '/dashboard'
                : tab.path.includes('?')
                ? location.pathname + location.search === tab.path
                : location.pathname.startsWith(tab.path);

            const hasRoseBadge = tab.badgeKey === 'threats' && highThreatsCount > 0;

            return (
              <NavLink
                key={tab.id}
                to={tab.path}
                className={`relative flex flex-col items-center justify-center w-14 sm:w-16 py-1 px-1 rounded-xl transition-all duration-200 group ${
                  isTabActive
                    ? 'bg-gradient-to-b from-blue-500/25 to-blue-600/10 text-white border border-blue-400/30 shadow-[0_0_18px_rgba(59,130,246,0.35)]'
                    : 'text-[#9AA3B8] hover:text-[#FFFFFF] hover:bg-white/[0.04] border border-transparent'
                }`}
              >
                <div className="relative flex items-center justify-center mb-0.5">
                  <i
                    className={`${tab.icon} text-base sm:text-lg transition-transform duration-150 group-hover:scale-110 ${
                      isTabActive ? 'text-white drop-shadow-[0_0_8px_rgba(96,165,250,0.8)]' : 'text-[#9AA3B8]'
                    }`}
                  ></i>
                  {hasRoseBadge && (
                    <span className="absolute -top-1 -right-1.5 w-1.5 h-1.5 rounded-full bg-[#EF4444] ring-2 ring-[#0B0F1A] shadow-[0_0_6px_#EF4444]" />
                  )}
                </div>
                <span
                  className={`text-[9.5px] tracking-tight leading-none ${
                    isTabActive ? 'font-semibold text-white' : 'font-medium text-[#9AA3B8]'
                  }`}
                >
                  {tab.label}
                </span>

                {/* Radiant Active Dot under bottom border */}
                {isTabActive && (
                  <span className="absolute -bottom-1.5 w-1 h-1 rounded-full bg-[#60A5FA] shadow-[0_0_8px_#60A5FA]" />
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>
    </div>
  );
};

export default AppShell;

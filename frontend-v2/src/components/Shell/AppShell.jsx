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
          background: 'rgba(9, 12, 22, 0.65)',
          backdropFilter: 'blur(24px) saturate(180%)',
          WebkitBackdropFilter: 'blur(24px) saturate(180%)',
        }}
      >
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-6">
          {/* Brand Mark */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-xl bg-[#2563EB]/20 border border-[#3B82F6]/40 flex items-center justify-center text-[#60A5FA] shadow-[0_0_15px_rgba(59,130,246,0.25)]">
              <i className="ri-shield-keyhole-fill text-lg"></i>
            </div>
            <div>
              <h1 className="font-bold text-base tracking-tight text-[#FFFFFF] leading-tight">
                NetVisor
              </h1>
              <p className="text-[10px] text-[#9AA3B8] font-medium leading-none">
                Network Security Monitor
              </p>
            </div>
          </div>

          {/* Centered Global Search Input (Exact to reference mockup) */}
          <div className="flex-1 max-w-lg hidden md:block">
            <div className="relative flex items-center">
              <i className="ri-search-line absolute left-3.5 text-[#5E6579] text-sm pointer-events-none"></i>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search devices, IPs, domains, users..."
                className="w-full h-9 pl-9 pr-12 rounded-xl bg-white/[0.04] hover:bg-white/[0.06] focus:bg-white/[0.08] border border-white/[0.08] focus:border-blue-500/50 text-xs text-[#F1F3F9] placeholder-[#5E6579] outline-none transition-all duration-150"
              />
              <span className="absolute right-3 px-1.5 py-0.5 rounded bg-white/[0.06] border border-white/[0.1] text-[10px] mono text-[#9AA3B8] pointer-events-none">
                ⌘ K
              </span>
            </div>
          </div>

          {/* Right Action Controls (Theme, Notifications, User Badge) */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Theme Toggle */}
            <button
              type="button"
              className="w-8 h-8 rounded-xl bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] flex items-center justify-center text-[#9AA3B8] hover:text-white transition-colors"
              title="Toggle theme"
            >
              <i className="ri-sun-line text-sm"></i>
            </button>

            {/* Notifications Bell with Unread Badge */}
            <button
              type="button"
              className="relative w-8 h-8 rounded-xl bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.06] flex items-center justify-center text-[#9AA3B8] hover:text-white transition-colors"
              title="System alerts"
            >
              <i className="ri-notification-3-line text-sm"></i>
              <span className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-[#EF4444] ring-2 ring-[#0B0F1A]" />
            </button>

            {/* User Profile Pill */}
            <div className="flex items-center gap-2.5 pl-2 py-1 pr-3 rounded-full bg-white/[0.03] border border-white/[0.06]">
              <div className="w-6 h-6 rounded-full bg-gradient-to-tr from-blue-500 to-indigo-500 flex items-center justify-center text-[11px] font-bold text-white shadow-sm">
                P
              </div>
              <div className="text-left hidden sm:block">
                <div className="text-xs font-semibold text-[#F1F3F9] leading-none">Premkumar</div>
                <div className="text-[9.5px] text-[#9AA3B8] leading-tight">Admin</div>
              </div>
              <i className="ri-arrow-down-s-line text-xs text-[#5E6579]"></i>
            </div>
          </div>
        </div>
      </header>

      {/* 3. Main Workspace Canvas */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 pt-6 pb-28">
        {children}
      </main>

      {/* 4. Floating Bottom Dock (Reference: Pill dock with soft glow) */}
      <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 pointer-events-none">
        <nav
          className="pointer-events-auto flex items-center gap-1.5 p-1.5 rounded-[22px] border border-white/[0.09]"
          style={{
            background: 'rgba(11, 15, 27, 0.78)',
            backdropFilter: 'blur(28px) saturate(180%)',
            WebkitBackdropFilter: 'blur(28px) saturate(180%)',
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.55), 0 0 1px 1px rgba(255, 255, 255, 0.05)',
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
                className={`relative flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all duration-200 ${
                  isActive
                    ? 'bg-blue-500/15 text-[#60A5FA] border border-blue-500/30 shadow-[0_0_12px_rgba(59,130,246,0.18)]'
                    : 'text-[#9AA3B8] hover:text-[#F1F3F9] hover:bg-white/[0.03] border border-transparent'
                }`}
              >
                <div className="relative flex items-center justify-center">
                  <i className={`${tab.icon} text-base`}></i>
                  {hasRoseBadge && (
                    <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-[#EF4444] ring-2 ring-[#0B0F1A] shadow-[0_0_8px_#EF4444]" />
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

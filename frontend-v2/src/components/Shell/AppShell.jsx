import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';

const TABS = [
  { id: 'dashboard', path: '/', label: 'Dashboard', icon: 'ri-dashboard-3-line' },
  { id: 'devices', path: '/devices', label: 'Devices', icon: 'ri-macbook-line' },
  { id: 'agents', path: '/agents', label: 'Agents', icon: 'ri-radar-line' },
  { id: 'apps', path: '/apps', label: 'Applications', icon: 'ri-apps-2-line' },
  { id: 'threats', path: '/threats', label: 'Threats', icon: 'ri-shield-flash-line', badgeKey: 'threats' },
  { id: 'activity', path: '/activity', label: 'Activity', icon: 'ri-pulse-line' },
  { id: 'vpn', path: '/vpn', label: 'VPN', icon: 'ri-shield-keyhole-line' },
  { id: 'settings', path: '/settings', label: 'Settings', icon: 'ri-settings-4-line' },
];

export const AppShell = ({
  children,
  socketStatus = 'connected',
  highThreatsCount = 0,
}) => {
  const location = useLocation();

  return (
    <div className="min-h-screen relative flex flex-col bg-[#05060B] text-[#F1F3F9]">
      {/* Fixed Background Layers */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        {/* Starfield Layer */}
        <div
          className="absolute inset-0 opacity-55"
          style={{
            backgroundImage: `
              radial-gradient(1px 1px at 25px 35px, rgba(255, 255, 255, 0.55), transparent),
              radial-gradient(1.2px 1.2px at 150px 120px, rgba(255, 255, 255, 0.45), transparent),
              radial-gradient(1.5px 1.5px at 280px 220px, rgba(255, 255, 255, 0.6), transparent),
              radial-gradient(1px 1px at 80px 290px, rgba(255, 255, 255, 0.5), transparent)
            `,
            backgroundSize: '340px 340px',
          }}
        />

        {/* Top-Center Anchored Nebula Glow */}
        <div
          className="absolute top-0 left-1/2 -translate-x-1/2 w-screen max-w-[1400px] h-[550px] pointer-events-none"
          style={{
            background: `
              radial-gradient(ellipse 65% 50% at 50% 0%, rgba(167, 139, 250, calc(0.18 * var(--nebula-intensity))) 0%, transparent 70%),
              radial-gradient(ellipse 55% 45% at 42% -5%, rgba(96, 165, 250, calc(0.22 * var(--nebula-intensity))) 0%, transparent 65%),
              radial-gradient(ellipse 40% 35% at 58% 10%, rgba(245, 158, 11, calc(0.12 * var(--nebula-intensity))) 0%, transparent 60%),
              radial-gradient(ellipse 50% 40% at 50% 18%, rgba(84, 200, 232, calc(0.14 * var(--nebula-intensity))) 0%, transparent 60%)
            `,
          }}
        />
      </div>

      {/* Topbar Header */}
      <header
        className="sticky top-0 z-40 w-full border-b border-white/[0.08]"
        style={{
          background: 'var(--glass-hi)',
          backdropFilter: 'blur(28px) saturate(180%)',
          WebkitBackdropFilter: 'blur(28px) saturate(180%)',
        }}
      >
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
          {/* Brand Mark */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-[#60A5FA] to-[#54C8E8] flex items-center justify-center text-[#05060B] font-extrabold shadow-md shadow-blue-500/20">
              <i className="ri-radar-fill text-lg"></i>
            </div>
            <div>
              <h1 className="font-extrabold text-base tracking-tight text-[#F1F3F9] flex items-center gap-2">
                NetVisor
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-500/10 text-[#60A5FA] border border-blue-500/20 mono">
                  v2.0
                </span>
              </h1>
              <p className="text-[10.5px] text-[#9AA3B8] font-medium leading-none">
                Cyber Security Workspace
              </p>
            </div>
          </div>

          {/* Right Status / Telemetry Stream Pill */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/5 text-xs text-[#9AA3B8]">
              <span
                className={`w-2 h-2 rounded-full ${
                  socketStatus === 'connected'
                    ? 'bg-[#34D399] shadow-[0_0_8px_#34D399]'
                    : 'bg-[#FB7185]'
                }`}
              />
              <span className="font-medium text-[#F1F3F9]">
                {socketStatus === 'connected' ? 'Gateway Live' : 'Disconnected'}
              </span>
            </div>

            <div className="w-8 h-8 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-xs font-bold text-[#F1F3F9]">
              NV
            </div>
          </div>
        </div>
      </header>

      {/* Main Workspace (With bottom clearance for floating tab bar) */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 pt-6 pb-28">
        {children}
      </main>

      {/* Floating Bottom Tab Bar (Fixed, Centered, Pill-shaped, Glass-hi) */}
      <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 pointer-events-none">
        <nav
          className="pointer-events-auto flex items-center gap-1.5 p-1.5 rounded-[20px] shadow-2xl border border-white/[0.09]"
          style={{
            background: 'var(--glass-hi)',
            backdropFilter: 'blur(28px) saturate(180%)',
            WebkitBackdropFilter: 'blur(28px) saturate(180%)',
            boxShadow: '0 16px 40px rgba(0, 0, 0, 0.45)',
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
                className={`relative flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all duration-150 ${
                  isActive
                    ? 'bg-[rgba(96,165,250,0.14)] text-[#60A5FA]'
                    : 'text-[#9AA3B8] hover:text-[#F1F3F9] hover:bg-white/[0.03]'
                }`}
              >
                <div className="relative flex items-center justify-center">
                  <i className={`${tab.icon} text-base`}></i>
                  {hasRoseBadge && (
                    <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-[#FB7185] ring-2 ring-[#181C2E] shadow-[0_0_6px_#FB7185]" />
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

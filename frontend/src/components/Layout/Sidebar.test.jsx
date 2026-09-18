import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Sidebar from './Sidebar';

let mockIsAdmin = true;

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    isAdmin: mockIsAdmin,
    user: mockIsAdmin ? { role: 'org_admin' } : { role: 'operator' },
  }),
}));

vi.mock('../../immersion/engine/useImmersion', () => ({
  useImmersion: () => ({
    activeTheme: { terminology: {} },
  }),
}));

vi.mock('../../utils/sound', () => ({
  playHoverSound: vi.fn(),
}));

describe('Sidebar', () => {
  it('renders all navigation links including Settings for admin users', () => {
    mockIsAdmin = true;
    render(
      <MemoryRouter>
        <Sidebar isCollapsed={false} isMobileOpen={false} onCloseMobile={vi.fn()} />
      </MemoryRouter>
    );

    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Devices')).toBeInTheDocument();
    expect(screen.getByText('Applications')).toBeInTheDocument();
    expect(screen.getByText('Fleet')).toBeInTheDocument();
    expect(screen.getByText('Web Inspection')).toBeInTheDocument();
    expect(screen.getByText('Threats')).toBeInTheDocument();
    expect(screen.getByText('Traffic')).toBeInTheDocument();
    expect(screen.getByText('Logs')).toBeInTheDocument();
    expect(screen.getByText('VPN')).toBeInTheDocument();
    expect(screen.getByText('Appearance')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('renders operational navigation links but omits Settings for non-admin operators', () => {
    mockIsAdmin = false;
    render(
      <MemoryRouter>
        <Sidebar isCollapsed={false} isMobileOpen={false} onCloseMobile={vi.fn()} />
      </MemoryRouter>
    );

    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Devices')).toBeInTheDocument();
    expect(screen.getByText('Applications')).toBeInTheDocument();
    expect(screen.getByText('Fleet')).toBeInTheDocument();
    expect(screen.getByText('Web Inspection')).toBeInTheDocument();
    expect(screen.getByText('Threats')).toBeInTheDocument();
    expect(screen.getByText('Traffic')).toBeInTheDocument();
    expect(screen.getByText('Logs')).toBeInTheDocument();
    expect(screen.getByText('VPN')).toBeInTheDocument();
    expect(screen.getByText('Appearance')).toBeInTheDocument();
    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import DevicesPage from './DevicesPage';
import { systemService } from '../services/api';

vi.mock('../services/api', () => ({
  systemService: {
    getDevices: vi.fn(),
  },
}));

vi.mock('../hooks/useVisibilityPolling', () => ({
  useVisibilityPolling: vi.fn(),
}));

vi.mock('../hooks/useWebSocket', () => ({
  useWebSocket: vi.fn(),
}));

const mockDevices = [
  {
    ip: '192.168.1.50',
    mac: '00:11:22:33:44:55',
    hostname: 'workstation-alpha',
    vendor: 'Dell Inc.',
    device_type: 'Desktop',
    os_family: 'Windows',
    management_mode: 'managed',
    status: 'Online',
    is_online: true,
    risk_level: 'LOW',
    risk_score: 10,
    identity_confidence: 0.95,
  },
  {
    ip: '192.168.1.120',
    mac: 'aa:bb:cc:dd:ee:ff',
    hostname: '',
    vendor: 'Apple, Inc.',
    device_type: 'Smartphone',
    os_family: 'iOS',
    management_mode: 'byod',
    status: 'Offline',
    is_online: false,
    top_application: null,
    risk_level: 'MEDIUM',
    risk_score: 45,
    identity_confidence: 0.60,
  },
];

describe('DevicesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    systemService.getDevices.mockResolvedValue({ data: mockDevices });
  });

  it('renders both managed and observed BYOD devices without premature filtering', async () => {
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('workstation-alpha')).toBeInTheDocument();
      expect(screen.getByText('Device 192.168.1.120')).toBeInTheDocument();
    });
  });

  it('filters devices by search query', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('workstation-alpha')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/search hostname, ip, mac/i);
    await user.type(searchInput, 'Dell');

    expect(screen.getByText('workstation-alpha')).toBeInTheDocument();
    expect(screen.queryByText('Device 192.168.1.120')).not.toBeInTheDocument();
  });
});

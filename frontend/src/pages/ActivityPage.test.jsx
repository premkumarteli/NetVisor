import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ActivityPage from './ActivityPage';
import { systemService } from '../services/api';

vi.mock('../services/api', () => ({
  systemService: {
    getStats: vi.fn(),
    getActivity: vi.fn(),
    getTrafficHistory: vi.fn(),
  },
}));

vi.mock('../hooks/useVisibilityPolling', () => ({
  useVisibilityPolling: vi.fn(),
}));

vi.mock('../hooks/useWebSocket', () => ({
  useWebSocket: vi.fn(),
}));

vi.mock('../components/Dashboard/TrafficChart', () => ({
  default: ({ data }) => (
    <div data-testid="traffic-chart">
      {data?.labels?.map((lbl, i) => (
        <span key={i} data-testid="chart-label">{lbl}</span>
      ))}
    </div>
  ),
}));

describe('ActivityPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    systemService.getStats.mockResolvedValue({
      data: {
        active_devices: 4,
        bandwidth_bytes_sec: 1024,
      },
    });
    systemService.getActivity.mockResolvedValue({
      data: [
        {
          timestamp: '2026-09-17T12:00:00Z',
          src_ip: '192.168.1.10',
          dst_ip: '93.184.216.34',
          protocol: 'TCP',
          application: 'HTTPS',
          byte_count: 500,
          severity: 'LOW',
        },
      ],
    });
    systemService.getTrafficHistory.mockResolvedValue({
      data: [
        { timestamp: '2026-09-17T10:30:00Z', byte_count: 60000 },
        { timestamp: '', byte_count: 0 },
        { timestamp: 'invalid-date', byte_count: 0 },
      ],
    });
  });

  it('safely handles empty or malformed timestamps without producing NaN:NaN', async () => {
    render(
      <MemoryRouter>
        <ActivityPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      const labels = screen.getAllByTestId('chart-label');
      expect(labels.length).toBe(4);
      // Valid historical timestamp formats to HH:mm
      expect(labels[0].textContent).toMatch(/^\d{2}:\d{2}$/);
      // Empty and invalid historical timestamps fall back safely to '--:--'
      expect(labels[1].textContent).toBe('--:--');
      expect(labels[2].textContent).toBe('--:--');
      // Live traffic timestamp added by fetchTraffic
      expect(labels[3].textContent).toMatch(/^\d{2}:\d{2}$/);
      // No labels contain NaN:NaN
      labels.forEach((lbl) => {
        expect(lbl.textContent).not.toContain('NaN');
      });
    });
  });
});

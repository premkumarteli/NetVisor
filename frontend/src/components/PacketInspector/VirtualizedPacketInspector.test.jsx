import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { VirtualizedPacketInspector } from './VirtualizedPacketInspector.jsx';

describe('VirtualizedPacketInspector', () => {
  const mockPackets = [
    {
      id: 1,
      flow_id: 'flow_1',
      src_ip: '192.168.1.10',
      dst_ip: '8.8.8.8',
      src_port: 54321,
      dst_port: 53,
      protocol: 'UDP',
      bytes: 84,
      dns_query: 'example.com',
      threat_indicator: '',
    },
    {
      id: 2,
      flow_id: 'flow_2',
      src_ip: '192.168.1.10',
      dst_ip: '1.1.1.1',
      src_port: 54322,
      dst_port: 443,
      protocol: 'TCP',
      bytes: 1420,
      tls_sni: 'api.github.com',
      threat_indicator: 'DATA_EXFILTRATION',
      risk_score: 90,
    },
  ];

  it('renders virtualized packet table with headers and rows', () => {
    render(<VirtualizedPacketInspector packets={mockPackets} height={600} />);

    expect(screen.getByRole('region', { name: /packet inspector/i })).toBeInTheDocument();
    expect(screen.getByText('192.168.1.10:54321')).toBeInTheDocument();
    expect(screen.getByText('8.8.8.8:53')).toBeInTheDocument();
    expect(screen.getAllByText('UDP').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('TCP').length).toBeGreaterThanOrEqual(1);
  });

  it('renders dissection tree and hex dump for selected packet', () => {
    const handleSelect = vi.fn();
    render(<VirtualizedPacketInspector packets={mockPackets} onPacketSelect={handleSelect} height={600} />);

    // Dissection tree titles
    expect(screen.getByText(/Protocol Dissection/i)).toBeInTheDocument();
    expect(screen.getByText(/Frame 1:/i)).toBeInTheDocument();
    expect(screen.getByText(/Internet Protocol Version 4/i)).toBeInTheDocument();

    // Hex dump header
    expect(screen.getByText(/Hex & ASCII Byte Stream/i)).toBeInTheDocument();
    expect(screen.getByText('0000')).toBeInTheDocument();
  });

  it('filters packets dynamically using NVQL input', () => {
    render(<VirtualizedPacketInspector packets={mockPackets} height={600} />);

    const input = screen.getByPlaceholderText(/Apply NVQL filter/i);
    const applyBtn = screen.getByRole('button', { name: /Apply/i });

    // Filter by DNS port 53
    fireEvent.change(input, { target: { value: 'udp.port == 53' } });
    fireEvent.click(applyBtn);

    expect(screen.getByText('192.168.1.10:54321')).toBeInTheDocument();
    expect(screen.queryByText('192.168.1.10:54322')).not.toBeInTheDocument();
  });

  it('navigates packets using keyboard ArrowDown', () => {
    const handleSelect = vi.fn();
    render(<VirtualizedPacketInspector packets={mockPackets} onPacketSelect={handleSelect} height={600} />);

    const container = screen.getByRole('region', { name: /packet inspector/i });
    fireEvent.keyDown(container, { key: 'ArrowDown' });

    // Dissection should update to second packet
    expect(screen.getByText(/Frame 2:/i)).toBeInTheDocument();
    expect(screen.getByText(/DATA_EXFILTRATION/i)).toBeInTheDocument();
  });
});

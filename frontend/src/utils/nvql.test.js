import { describe, it, expect } from 'vitest';
import { NVQL } from './nvql.js';

describe('NetVisor Query Language (NVQL)', () => {
  const samplePacket = {
    id: 101,
    src_ip: '192.168.1.50',
    dst_ip: '8.8.8.8',
    src_port: 54321,
    dst_port: 443,
    protocol: 'TCP',
    bytes: 1420,
    dns_query: '',
    tls_sni: 'secure.cloud.net',
    threat_indicator: 'PORT_SCAN',
    risk_score: 85,
  };

  it('validates correct and incorrect queries', () => {
    expect(NVQL.validate('ip.src == 192.168.1.50').valid).toBe(true);
    expect(NVQL.validate('(tcp.port == 443 || udp.port == 53) && frame.len > 100').valid).toBe(true);
    expect(NVQL.validate('ip.src ==').valid).toBe(false);
    expect(NVQL.validate('(ip.src == 1.1.1.1').valid).toBe(false);
  });

  it('evaluates simple equality and numeric filters', () => {
    const matchIp = NVQL.compile('ip.src == 192.168.1.50');
    expect(matchIp(samplePacket)).toBe(true);

    const nonMatchIp = NVQL.compile('ip.src == 10.0.0.1');
    expect(nonMatchIp(samplePacket)).toBe(false);

    const matchPort = NVQL.compile('tcp.port == 443');
    expect(matchPort(samplePacket)).toBe(true);

    const matchLen = NVQL.compile('frame.len > 1000');
    expect(matchLen(samplePacket)).toBe(true);

    const smallLen = NVQL.compile('frame.len < 500');
    expect(smallLen(samplePacket)).toBe(false);
  });

  it('evaluates boolean operators AND, OR, and NOT', () => {
    const andMatch = NVQL.compile('ip.src == 192.168.1.50 && tcp.port == 443');
    expect(andMatch(samplePacket)).toBe(true);

    const andFail = NVQL.compile('ip.src == 192.168.1.50 && tcp.port == 80');
    expect(andFail(samplePacket)).toBe(false);

    const orMatch = NVQL.compile('tcp.port == 80 || tcp.port == 443');
    expect(orMatch(samplePacket)).toBe(true);

    const notMatch = NVQL.compile('!(tcp.port == 80)');
    expect(notMatch(samplePacket)).toBe(true);
  });

  it('evaluates string contains and multi-field matching', () => {
    const sniContains = NVQL.compile('tls.handshake.sni contains "cloud"');
    expect(sniContains(samplePacket)).toBe(true);

    const sniNoMatch = NVQL.compile('tls.handshake.sni contains "evil"');
    expect(sniNoMatch(samplePacket)).toBe(false);

    const threatFilter = NVQL.compile('threat.detected && threat.indicator contains "scan"');
    expect(threatFilter(samplePacket)).toBe(true);
  });

  it('evaluates global search query terms', () => {
    const searchTcp = NVQL.compile('tcp');
    expect(searchTcp(samplePacket)).toBe(true);

    const searchGoogleDns = NVQL.compile('8.8.8.8');
    expect(searchGoogleDns(samplePacket)).toBe(true);

    const searchUdp = NVQL.compile('udp');
    expect(searchUdp(samplePacket)).toBe(false);
  });
});

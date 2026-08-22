/**
 * NetVisor Human Translation Layer (Cyber Intelligence & Network Presentation)
 * Transforms raw backend telemetry, cryptic detection keys, and network codes
 * into clear, actionable, plain-English insights for security analysts and administrators.
 */

// Well-known cloud and infrastructure IP prefix mappings
const KNOWN_IP_RANGES = [
  { prefix: '10.', name: 'Internal Corporate Subnet', type: 'private' },
  { prefix: '192.168.', name: 'Local Network Asset', type: 'private' },
  { prefix: '172.16.', name: 'Private Subnet', type: 'private' },
  { prefix: '172.17.', name: 'Docker / Container Network', type: 'private' },
  { prefix: '172.18.', name: 'Container Subnet', type: 'private' },
  { prefix: '172.19.', name: 'Container Subnet', type: 'private' },
  { prefix: '172.20.', name: 'Private Subnet', type: 'private' },
  { prefix: '172.31.', name: 'Private Subnet', type: 'private' },
  { prefix: '127.', name: 'Localhost Loopback', type: 'loopback' },
  { prefix: '142.250.', name: 'Google Cloud Services', type: 'cloud' },
  { prefix: '172.217.', name: 'Google Web Infrastructure', type: 'cloud' },
  { prefix: '13.107.', name: 'Microsoft 365 / Azure', type: 'cloud' },
  { prefix: '20.190.', name: 'Microsoft Azure Services', type: 'cloud' },
  { prefix: '52.', name: 'AWS Cloud Services', type: 'cloud' },
  { prefix: '54.', name: 'AWS Infrastructure', type: 'cloud' },
  { prefix: '104.16.', name: 'Cloudflare CDN & Edge', type: 'cloud' },
  { prefix: '104.17.', name: 'Cloudflare CDN & Edge', type: 'cloud' },
  { prefix: '104.244.', name: 'X / Twitter Services', type: 'social' },
  { prefix: '157.240.', name: 'Meta / Facebook Network', type: 'social' },
  { prefix: '151.101.', name: 'Fastly Edge CDN', type: 'cloud' },
  { prefix: '23.', name: 'Akamai CDN Network', type: 'cloud' },
  { prefix: '1.1.1.1', name: 'Cloudflare Public DNS', type: 'dns' },
  { prefix: '8.8.8.8', name: 'Google Public DNS', type: 'dns' },
  { prefix: '8.8.4.4', name: 'Google Public DNS', type: 'dns' },
];

const KNOWN_PORTS = {
  20: 'FTP Data',
  21: 'FTP Control',
  22: 'SSH Remote Access',
  23: 'Telnet (Unencrypted)',
  25: 'SMTP Email',
  53: 'DNS Resolution',
  80: 'Web Traffic (HTTP)',
  110: 'POP3 Email',
  123: 'NTP Time Sync',
  143: 'IMAP Email',
  443: 'Encrypted Web (HTTPS/TLS)',
  445: 'SMB File Sharing',
  993: 'Secure IMAP',
  995: 'Secure POP3',
  1194: 'OpenVPN Tunnel',
  3389: 'RDP Remote Desktop',
  5060: 'SIP VoIP',
  8080: 'Alternate HTTP Web',
  8443: 'Alternate HTTPS Web',
  51820: 'WireGuard VPN Tunnel',
};

const KNOWN_DETECTIONS = [
  {
    pattern: /dns_tunnel/i,
    title: 'Suspected DNS Tunneling Exfiltration',
    summary: 'A device is encoding non-DNS data into domain lookups. Often used by malware or unauthorized tunnels to bypass firewalls.',
    impact: 'Potential data theft, command-and-control communication, or corporate policy bypass.',
    recommendation: 'Inspect active background processes on the client device. Block anomalous domain requests on the internal DNS resolver.',
  },
  {
    pattern: /port_scan|syn_scan|scan/i,
    title: 'Port Scanning / Network Reconnaissance',
    summary: 'Rapid sequential connection attempts across multiple ports detected. Indicates host discovery or vulnerability probing.',
    impact: 'Attacker or compromised device mapping out internal services before launching an exploit.',
    recommendation: 'Temporarily isolate the source IP from other internal VLANs and review endpoint activity logs.',
  },
  {
    pattern: /tor_exit|tor_node|tor/i,
    title: 'Tor Anonymization Network Routing',
    summary: 'Connection established to known Tor exit node or bridge relays.',
    impact: 'Traffic is masked from compliance auditing and may involve unauthorized darknet browsing.',
    recommendation: 'Verify if Tor usage is authorized by company policy. Enforce firewall gateway rules to block known Tor directory relays.',
  },
  {
    pattern: /vpn_provider|vpn_leak|commercial_vpn/i,
    title: 'Commercial VPN Tunnel Detected',
    summary: 'Encrypted tunnel established with a public commercial VPN provider, masking user browsing from security inspection.',
    impact: 'Loss of deep packet visibility and corporate compliance data governance.',
    recommendation: 'Check endpoint compliance policies. Enforce proxy settings on managed client browsers.',
  },
  {
    pattern: /crypto_miner|stratum|mining/i,
    title: 'Cryptocurrency Mining Activity',
    summary: 'Outbound communication matches Stratum mining pool protocols.',
    impact: 'Unauthorized hardware resource consumption and possible cryptojacking malware infection.',
    recommendation: 'Scan client machine for unauthorized miner executables or rogue browser extensions.',
  },
  {
    pattern: /syn_flood|ddos|flood/i,
    title: 'SYN Flood / Denial of Service Surge',
    summary: 'Abnormal flood of incomplete TCP SYN handshakes overwhelming connection tables.',
    impact: 'Service degradation and exhaustion of gateway state tables.',
    recommendation: 'Enable SYN cookies on gateway/firewall and rate-limit the attacking source IP.',
  },
  {
    pattern: /tls_ja3|fingerprint_anomaly/i,
    title: 'Anomalous TLS Client Signature',
    summary: 'The client TLS handshake parameters do not match standard operating system or web browser profiles.',
    impact: 'Possible scripted automation, scraper, custom RAT, or non-standard client software.',
    recommendation: 'Verify the executable originating the TLS session via the host agent.',
  },
  {
    pattern: /beaconing|c2|command_control/i,
    title: 'Periodic Command-and-Control Beaconing',
    summary: 'Fixed-interval outbound heartbeat signals detected to an external server.',
    impact: 'Active malware persistence or remote shell awaiting operator instructions.',
    recommendation: 'Immediately quarantine endpoint and capture a memory dump for forensic analysis.',
  },
  {
    pattern: /high_bandwidth|traffic_surge|bandwidth_surge/i,
    title: 'Unusual High-Volume Bandwidth Spike',
    summary: 'Data transfer volume sharply exceeded the 24-hour historical baseline for this asset.',
    impact: 'Could indicate large file upload, bulk backup, video stream, or unauthorized data export.',
    recommendation: 'Check whether a scheduled backup or large file transfer was initiated by the user.',
  },
];

/**
 * Translates raw threat detection strings into clear, human-understandable audit objects
 */
export function translateThreat(threat = {}) {
  const rawDetection = threat.breakdown?.primary_detection || threat.message || threat.detection || 'Unknown Detection';
  const severity = String(threat.severity || 'HIGH').toUpperCase();
  const rawScore = Number(threat.risk_score) || (severity === 'CRITICAL' ? 95 : severity === 'HIGH' ? 80 : severity === 'MEDIUM' ? 50 : 20);

  let match = KNOWN_DETECTIONS.find((d) => d.pattern.test(rawDetection));

  if (!match) {
    // Generate clean fallback based on title casing
    const cleanTitle = rawDetection
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());

    match = {
      title: cleanTitle,
      summary: `Automated detection triggered with an anomaly risk score of ${Math.round(rawScore)}%.`,
      impact: 'Unusual network behavior detected that deviates from expected operational baselines.',
      recommendation: 'Review the source host connection logs and verify with the asset owner.',
    };
  }

  return {
    rawKey: rawDetection,
    title: match.title,
    summary: match.summary,
    impact: match.impact,
    recommendation: match.recommendation,
    severity,
    riskScore: Math.round(rawScore),
    targetAsset: threat.device_ip || threat.src_ip || 'Unassigned Host',
    destination: threat.domain || threat.dst_ip || 'External Destination',
    vpnProvider: threat.breakdown?.vpn_provider || null,
  };
}

/**
 * Translates unknown / raw destinations into recognizable organization or cloud provider names
 */
export function translateDestination(dst_ip = '', domain = '', port = null, protocol = '', application = '') {
  const cleanApp = String(application || '').trim();
  const cleanDomain = String(domain || '').trim();
  const cleanIp = String(dst_ip || '').trim();

  // If application is well-known and not generic, keep it
  if (cleanApp && !['other', 'unknown', 'raw', '-'].includes(cleanApp.toLowerCase())) {
    return {
      primary: cleanApp,
      meta: cleanDomain || cleanIp || 'Application Session',
      isKnown: true,
    };
  }

  // If a readable domain exists, use domain
  if (cleanDomain && cleanDomain !== '-' && !cleanDomain.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
    // Extract base domain for human clarity
    const parts = cleanDomain.split('.');
    const baseName = parts.length > 2 ? parts.slice(-2).join('.') : cleanDomain;
    const humanName = baseName.charAt(0).toUpperCase() + baseName.slice(1);

    return {
      primary: humanName,
      meta: `${cleanDomain}${port ? ` : ${port}` : ''}`,
      isKnown: true,
    };
  }

  // Look up known IP blocks
  const matchedRange = KNOWN_IP_RANGES.find((r) => cleanIp.startsWith(r.prefix));
  if (matchedRange) {
    const portDesc = port && KNOWN_PORTS[port] ? ` (${KNOWN_PORTS[port]})` : '';
    return {
      primary: matchedRange.name,
      meta: `${cleanIp}${port ? ` : ${port}` : ''}${portDesc}`,
      isKnown: true,
    };
  }

  // Port-based inference
  if (port && KNOWN_PORTS[port]) {
    return {
      primary: KNOWN_PORTS[port],
      meta: `${cleanIp} : ${port} (${protocol || 'TCP'})`,
      isKnown: false,
    };
  }

  // Fallback
  return {
    primary: cleanIp ? `Outbound Host ${cleanIp}` : 'External Service',
    meta: `${cleanIp || 'Direct socket'}${port ? `:${port}` : ''}`,
    isKnown: false,
  };
}

/**
 * Formats a timestamp into human relative time ("Just now", "2m ago", "3h ago")
 */
export function formatRelativeTime(value) {
  if (!value) return 'Unknown';

  const raw = String(value).trim();
  if (!raw) return 'Unknown';

  const normalized = raw.includes('T') ? raw : raw.replace(' ', 'T');
  const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/.test(normalized);
  const date = new Date(hasTimezone ? normalized : `${normalized}Z`);

  if (Number.isNaN(date.getTime())) return raw;

  const now = new Date();
  const diffSeconds = Math.max(0, Math.floor((now.getTime() - date.getTime()) / 1000));

  if (diffSeconds < 45) return 'Just now';
  if (diffSeconds < 90) return '1m ago';
  if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
  if (diffSeconds < 7200) return '1h ago';
  if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
  if (diffSeconds < 172800) return 'Yesterday';
  return `${Math.floor(diffSeconds / 86400)}d ago`;
}

/**
 * Translates telemetry source and confidence into clear analyst terminology
 */
export function translateTelemetrySource(source = '', confidence = null) {
  const s = String(source || '').toLowerCase();
  let label = 'Network Flow Heuristic';
  let badgeTone = 'neutral';

  if (s.includes('kernel') || s.includes('agent') || s.includes('direct')) {
    label = 'Host Agent (Verified)';
    badgeTone = 'success';
  } else if (s.includes('dpi') || s.includes('inspection')) {
    label = 'Deep Packet Inspection';
    badgeTone = 'accent';
  } else if (s.includes('zeek') || s.includes('bro')) {
    label = 'Zeek Network Protocol Analyzer';
    badgeTone = 'secondary';
  } else if (s.includes('heuristic') || s.includes('ai') || s.includes('model')) {
    label = 'Behavioral Anomaly Engine';
    badgeTone = 'warning';
  }

  const numericConf = Number(confidence);
  const confidencePercent = !Number.isNaN(numericConf) && numericConf > 0 ? `${Math.round(numericConf > 1 ? numericConf : numericConf * 100)}% confidence` : null;

  return {
    label,
    confidencePercent,
    badgeTone,
  };
}

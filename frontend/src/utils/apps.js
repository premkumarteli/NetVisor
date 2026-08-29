const GENERIC_TRANSPORT_APPLICATIONS = new Set([
  'ARP',
  'DHCP',
  'DNS',
  'HTTP',
  'HTTPS',
  'ICMP',
  'ICMPV6',
  'LLMNR',
  'MDNS',
  'NBDS',
  'NBNS',
  'NTP',
  'QUIC',
  'SSDP',
  'TCP',
  'TLS',
  'UDP',
]);

const NETWORK_SERVICE_APPLICATIONS = new Set([
  ...GENERIC_TRANSPORT_APPLICATIONS,
  'OTHER',
  'UNKNOWN',
]);

const NETWORK_SERVICE_VISUAL = {
  icon: 'ri-radar-line',
  accent: '#38bdf8',
  background: 'rgba(56, 189, 248, 0.14)',
  label: 'SV',
};

const APP_VISUALS = {
  Claude: {
    icon: 'ri-sparkling-fill',
    accent: '#d97706',
    background: 'rgba(217, 119, 6, 0.16)',
    label: 'CL',
  },
  'Claude AI': {
    icon: 'ri-sparkling-fill',
    accent: '#d97706',
    background: 'rgba(217, 119, 6, 0.16)',
    label: 'CL',
  },
  ChatGPT: {
    icon: 'ri-robot-2-fill',
    accent: '#10a37f',
    background: 'rgba(16, 163, 127, 0.16)',
    label: 'AI',
  },
  'Chat GPT': {
    icon: 'ri-robot-2-fill',
    accent: '#10a37f',
    background: 'rgba(16, 163, 127, 0.16)',
    label: 'AI',
  },
  Gemini: {
    icon: 'ri-magic-fill',
    accent: '#818cf8',
    background: 'rgba(129, 140, 248, 0.16)',
    label: 'GM',
  },
  'Google Gemini': {
    icon: 'ri-magic-fill',
    accent: '#818cf8',
    background: 'rgba(129, 140, 248, 0.16)',
    label: 'GM',
  },
  Sentry: {
    icon: 'ri-shield-check-line',
    accent: '#6366f1',
    background: 'rgba(99, 102, 241, 0.16)',
    label: 'ST',
  },
  YouTube: {
    icon: 'ri-youtube-fill',
    accent: '#ff3b30',
    background: 'rgba(255, 59, 48, 0.14)',
    label: 'YT',
  },
  Instagram: {
    icon: 'ri-instagram-fill',
    accent: '#ff7a59',
    background: 'rgba(255, 122, 89, 0.14)',
    label: 'IG',
  },
  Facebook: {
    icon: 'ri-facebook-circle-fill',
    accent: '#1877f2',
    background: 'rgba(24, 119, 242, 0.14)',
    label: 'FB',
  },
  WhatsApp: {
    icon: 'ri-whatsapp-fill',
    accent: '#25d366',
    background: 'rgba(37, 211, 102, 0.14)',
    label: 'WA',
  },
  Google: {
    icon: 'ri-google-fill',
    accent: '#4285f4',
    background: 'rgba(66, 133, 244, 0.14)',
    label: 'GG',
  },
  'Google Search': {
    icon: 'ri-search-line',
    accent: '#4285f4',
    background: 'rgba(66, 133, 244, 0.14)',
    label: 'GG',
  },
  'Google Apis': {
    icon: 'ri-cloud-fill',
    accent: '#34a853',
    background: 'rgba(52, 168, 83, 0.14)',
    label: 'API',
  },
  'Google Play': {
    icon: 'ri-google-play-fill',
    accent: '#00875a',
    background: 'rgba(0, 135, 90, 0.14)',
    label: 'GP',
  },
  'Google Services': {
    icon: 'ri-google-fill',
    accent: '#34d399',
    background: 'rgba(52, 211, 153, 0.14)',
    label: 'GS',
  },
  Microsoft: {
    icon: 'ri-windows-fill',
    accent: '#5e5ce6',
    background: 'rgba(94, 92, 230, 0.14)',
    label: 'MS',
  },
  'Bing Search': {
    icon: 'ri-search-2-line',
    accent: '#008373',
    background: 'rgba(0, 131, 115, 0.14)',
    label: 'BN',
  },
  GitHub: {
    icon: 'ri-github-fill',
    accent: '#94a3b8',
    background: 'rgba(148, 163, 184, 0.14)',
    label: 'GH',
  },
  Spotify: {
    icon: 'ri-spotify-fill',
    accent: '#22c55e',
    background: 'rgba(34, 197, 94, 0.14)',
    label: 'SP',
  },
  Slack: {
    icon: 'ri-slack-fill',
    accent: '#e01e5a',
    background: 'rgba(224, 30, 90, 0.14)',
    label: 'SL',
  },
  Discord: {
    icon: 'ri-discord-fill',
    accent: '#5865f2',
    background: 'rgba(88, 101, 242, 0.14)',
    label: 'DC',
  },
  Notion: {
    icon: 'ri-booklet-line',
    accent: '#e2e8f0',
    background: 'rgba(226, 232, 240, 0.14)',
    label: 'NO',
  },
  Perplexity: {
    icon: 'ri-bubble-chart-fill',
    accent: '#22c55e',
    background: 'rgba(34, 197, 94, 0.14)',
    label: 'PX',
  },
  'Visual Studio Code': {
    icon: 'ri-code-s-line',
    accent: '#007acc',
    background: 'rgba(0, 122, 204, 0.14)',
    label: 'VS',
  },
  VTU: {
    icon: 'ri-graduation-cap-fill',
    accent: '#f59e0b',
    background: 'rgba(245, 158, 11, 0.14)',
    label: 'VTU',
  },
  'Acharya Institutes': {
    icon: 'ri-building-4-fill',
    accent: '#3b82f6',
    background: 'rgba(59, 130, 246, 0.14)',
    label: 'ACH',
  },
  'Acharya ERP': {
    icon: 'ri-building-4-fill',
    accent: '#3b82f6',
    background: 'rgba(59, 130, 246, 0.14)',
    label: 'ACH',
  },
  RailOne: {
    icon: 'ri-train-fill',
    accent: '#06b6d4',
    background: 'rgba(6, 182, 212, 0.14)',
    label: 'RO',
  },
  IRCTC: {
    icon: 'ri-train-fill',
    accent: '#0284c7',
    background: 'rgba(2, 132, 199, 0.14)',
    label: 'IR',
  },
  HDHub4u: {
    icon: 'ri-movie-2-fill',
    accent: '#ec4899',
    background: 'rgba(236, 72, 153, 0.14)',
    label: 'HD',
  },
  Cursor: {
    icon: 'ri-code-box-line',
    accent: '#00f5ff',
    background: 'rgba(0, 245, 255, 0.14)',
    label: 'CU',
  },
  Antigravity: {
    icon: 'ri-shield-flash-line',
    accent: '#10b981',
    background: 'rgba(16, 185, 129, 0.14)',
    label: 'AG',
  },
  Grammarly: {
    icon: 'ri-edit-line',
    accent: '#22c55e',
    background: 'rgba(34, 197, 94, 0.14)',
    label: 'GR',
  },
  'Azure CloudApp': {
    icon: 'ri-cloud-line',
    accent: '#38bdf8',
    background: 'rgba(56, 189, 248, 0.14)',
    label: 'AZ',
  },
  Other: {
    icon: 'ri-global-line',
    accent: '#00f5ff',
    background: 'rgba(0, 245, 255, 0.12)',
    label: 'OT',
  },
};

function normalizeApplicationName(appName) {
  return String(appName || '').trim().toUpperCase();
}

export function isGenericTransportApplication(appName) {
  return GENERIC_TRANSPORT_APPLICATIONS.has(normalizeApplicationName(appName));
}

export function isNetworkServiceApplication(appName) {
  return NETWORK_SERVICE_APPLICATIONS.has(normalizeApplicationName(appName));
}

export function getApplicationKind(appName) {
  return isNetworkServiceApplication(appName) ? 'network-service' : 'product';
}

/**
 * Deterministically generates badge initials and safe branding colors for dynamic applications.
 * Guard: Strictly excludes Red (345° - 20°) and Amber (35° - 55°) to prevent collision
 * with system alerts/threat indicators.
 */
export function getGenerativeAppVisual(appName) {
  const clean = String(appName || '').trim();
  if (!clean) return APP_VISUALS.Other;

  // 1. Compute Label Initials
  const words = clean.split(/\s+/).filter(Boolean);
  let label = 'AP';
  if (words.length >= 2) {
    label = (words[0][0] + words[1][0]).toUpperCase();
  } else if (clean.length >= 2) {
    label = clean.slice(0, 2).toUpperCase();
  } else if (clean.length === 1) {
    label = clean.toUpperCase() + 'P';
  }

  // 2. Compute String Hash
  let hash = 0;
  for (let i = 0; i < clean.length; i += 1) {
    hash = clean.charCodeAt(i) + ((hash << 5) - hash);
    hash &= hash; // Convert to 32bit integer
  }
  const posHash = Math.abs(hash);

  // 3. Map into Non-Colliding Safe Hue Range:
  // Safe bands: [60°, 340°] (Total 280° range: Greens, Cyans, Blues, Purples, Violets, Magentas)
  const safeHue = 60 + (posHash % 280);
  const saturation = 70 + (posHash % 15); // 70-85%
  const lightness = 58 + (posHash % 10);  // 58-68%

  const accent = `hsl(${safeHue}, ${saturation}%, ${lightness}%)`;
  const background = `hsla(${safeHue}, ${saturation}%, ${lightness}%, 0.14)`;

  // 4. Keyword-guided icon selection
  const lower = clean.toLowerCase();
  let icon = 'ri-apps-2-line';
  if (lower.includes('api') || lower.includes('microservice')) icon = 'ri-cpu-line';
  else if (lower.includes('cloud') || lower.includes('aws') || lower.includes('azure')) icon = 'ri-cloud-line';
  else if (lower.includes('data') || lower.includes('db') || lower.includes('sql')) icon = 'ri-database-2-line';
  else if (lower.includes('mail') || lower.includes('email')) icon = 'ri-mail-line';
  else if (lower.includes('auth') || lower.includes('login') || lower.includes('identity')) icon = 'ri-key-2-line';
  else if (lower.includes('code') || lower.includes('dev') || lower.includes('git')) icon = 'ri-code-line';
  else if (lower.includes('crm') || lower.includes('sale') || lower.includes('shop') || lower.includes('store')) icon = 'ri-shopping-bag-line';
  else if (lower.includes('pay') || lower.includes('bill') || lower.includes('bank')) icon = 'ri-bank-card-line';
  else if (lower.includes('chat') || lower.includes('message') || lower.includes('talk')) icon = 'ri-message-3-line';
  else if (lower.includes('stream') || lower.includes('video') || lower.includes('tv')) icon = 'ri-movie-line';
  else if (lower.includes('doc') || lower.includes('wiki') || lower.includes('notes')) icon = 'ri-file-text-line';
  else if (lower.includes('search')) icon = 'ri-search-line';

  return {
    icon,
    accent,
    background,
    label,
  };
}

export function getApplicationVisual(appName) {
  if (isNetworkServiceApplication(appName)) {
    return NETWORK_SERVICE_VISUAL;
  }
  const clean = String(appName || '').trim();
  if (APP_VISUALS[clean]) {
    return APP_VISUALS[clean];
  }

  // Check case-insensitive match in predefined visuals
  const lower = clean.toLowerCase();
  for (const [key, visual] of Object.entries(APP_VISUALS)) {
    if (key.toLowerCase() === lower) {
      return visual;
    }
  }

  // Return generative visual for dynamically detected applications
  return getGenerativeAppVisual(clean);
}

export function formatRuntime(totalSeconds) {
  const seconds = Math.max(Math.trunc(Number(totalSeconds) || 0), 0);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  return `${remainingSeconds}s`;
}

const URL_NOISE_PATTERNS = [
  /gen_204/i,
  /domainreliability/i,
  /favicon\.ico/i,
  /\/complete\/search/i,
  /\/xjs\/_/i,
  /\/pagead\//i,
  /\/verify\//i,
  /play\.google\.com\/log/i,
  /\/log\?/i,
  /\/telemetry/i,
  /\/ces\//i,
  /\/cdn\/assets\//i,
  /clients\d*\.google\.com/i,
  /ogads-pa\.clients\d*\.google\.com/i,
  /safebrowsing\.googleapis/i,
  /update\.googleapis\.com\/service\/update2/i,
  /google\.internal\.onegoogle/i,
  /backend-anon\/settings/i,
  /backend-api\/sentinel/i,
  /sentinel\/ping/i,
  /sentinel\/2026/i,
  /async\/newtab/i,
  /async\/ddljson/i,
];

const hostFromUrl = (value) => {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    return new URL(raw).hostname;
  } catch {
    return raw;
  }
};

export const isDpiNoise = (entry) => {
  const pageUrl = String(entry?.page_url || '').trim();
  const domain = String(entry?.base_domain || entry?.domain || hostFromUrl(pageUrl)).trim().toLowerCase();
  const category = String(entry?.content_category || '').trim().toLowerCase();
  const title = String(entry?.page_title || entry?.group_label || '').trim().toLowerCase();

  if (URL_NOISE_PATTERNS.some((pattern) => pattern.test(pageUrl) || pattern.test(domain) || pattern.test(title))) {
    return true;
  }

  if (category === 'system' && ['safe', 'low', ''].includes(String(entry?.risk_level || '').toLowerCase())) {
    return true;
  }

  return false;
};

export const beautifyDpiUrl = (value) => {
  const raw = String(value || '').trim();
  if (!raw) return '-';

  try {
    const url = new URL(raw);
    const query = new URLSearchParams(url.search);
    const path = url.pathname === '/' ? '' : url.pathname;

    if (query.has('q')) {
      return `${url.hostname}${path} ?q=${query.get('q')}`;
    }

    const keys = Array.from(query.keys()).filter(Boolean);
    if (keys.length > 0) {
      return `${url.hostname}${path} ?(${keys.slice(0, 2).join(', ')}${keys.length > 2 ? '...' : ''})`;
    }

    return `${url.hostname}${path || ''}`;
  } catch {
    return raw.length > 96 ? `${raw.slice(0, 96)}...` : raw;
  }
};

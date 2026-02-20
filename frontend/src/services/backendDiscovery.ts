export function normalizeBaseUrl(value: string) {
  return value.trim().replace(/\/+$/, '');
}

function getDiscoveryCandidates() {
  const explicit = import.meta.env.VITE_API_BASE_URL;
  const list: string[] = [];

  if (explicit && explicit.trim()) {
    list.push(normalizeBaseUrl(explicit));
  }

  list.push('/api/v1');

  const origin = window.location.origin;
  list.push(`${origin}/api/v1`);

  if (window.location.port !== '3000') {
    list.push(`${window.location.protocol}//${window.location.hostname}:3000/api/v1`);
  }

  return Array.from(new Set(list.map(normalizeBaseUrl)));
}

async function probe(baseUrl: string) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 1600);
  try {
    const res = await fetch(`${baseUrl}/health`, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
      },
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    window.clearTimeout(timer);
  }
}

export async function discoverBackendBaseUrl() {
  const candidates = getDiscoveryCandidates();
  for (const candidate of candidates) {
    const ok = await probe(candidate);
    if (ok) {
      return normalizeBaseUrl(candidate);
    }
  }
  throw new Error('Unable to discover LucentID backend. Set VITE_API_BASE_URL or enter base URL manually.');
}

function canonicalJson(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return JSON.stringify(value ?? {});
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return JSON.stringify(value, keys);
}

async function hmacSha256Hex(secret: string, payload: string) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signed = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(signed))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function createSignedHeaders(secret: string, body: unknown, nonce?: string, timestamp?: string) {
  const ts = timestamp ?? `${Date.now()}`;
  const nonceValue = nonce ?? randomNonce(18);
  const payload = `${ts}.${nonceValue}.${canonicalJson(body ?? {})}`;
  const signature = await hmacSha256Hex(secret, payload);

  return {
    'x-request-timestamp': ts,
    'x-request-nonce': nonceValue,
    'x-request-signature': signature,
  };
}

export function randomNonce(byteLength = 18) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let base64 = btoa(String.fromCharCode(...bytes));
  base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return base64;
}

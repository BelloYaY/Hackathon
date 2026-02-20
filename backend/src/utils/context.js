const { sha256 } = require('./security');

function fingerprint({ tenantId, userId, deviceId, userAgent }) {
  const canonical = `${tenantId}|${userId}|${deviceId}|${(userAgent || '').trim().toLowerCase()}`;
  return sha256(canonical);
}

function parseBearer(authorization) {
  if (!authorization) {
    return null;
  }
  const [scheme, token] = authorization.split(' ');
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') {
    return null;
  }
  return token.trim();
}

function parseRoles(rolesJson) {
  try {
    const parsed = JSON.parse(rolesJson);
    return Array.isArray(parsed) ? parsed : ['user'];
  } catch {
    return ['user'];
  }
}

function normalizeIp(ip) {
  if (!ip) {
    return '0.0.0.0';
  }
  const trimmed = ip.split(',')[0].trim();
  if (trimmed.startsWith('::ffff:')) {
    return trimmed.slice(7);
  }
  if (trimmed === '::1') {
    return '127.0.0.1';
  }
  return trimmed;
}

function isoNowWithoutMs() {
  const now = new Date();
  now.setMilliseconds(0);
  return now.toISOString();
}

module.exports = {
  fingerprint,
  parseBearer,
  parseRoles,
  normalizeIp,
  isoNowWithoutMs,
};

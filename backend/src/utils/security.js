const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function nowIso() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
}

function toDate(value) {
  return value instanceof Date ? value : new Date(value);
}

function id(prefix) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function randomToken(bytes = 48) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function hashPassword(password, pepper = '') {
  const salt = crypto.randomBytes(16);
  const N = 16384;
  const r = 8;
  const p = 1;
  const keylen = 32;
  const digest = crypto.scryptSync(`${password}${pepper}`, salt, keylen, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64url')}$${digest.toString('base64url')}`;
}

function verifyPassword(password, encoded, pepper = '') {
  try {
    const [method, N, r, p, saltB64, digestB64] = encoded.split('$');
    if (method !== 'scrypt') {
      return false;
    }
    const salt = Buffer.from(saltB64, 'base64url');
    const expected = Buffer.from(digestB64, 'base64url');
    const actual = crypto.scryptSync(`${password}${pepper}`, salt, expected.length, {
      N: Number(N),
      r: Number(r),
      p: Number(p),
    });
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function signJwt(payload, settings, ttlSeconds) {
  return jwt.sign(payload, settings.jwtSecret, {
    algorithm: 'HS256',
    issuer: settings.jwtIssuer,
    audience: settings.jwtAudience,
    expiresIn: ttlSeconds,
    notBefore: 0,
  });
}

function verifyJwt(token, settings) {
  return jwt.verify(token, settings.jwtSecret, {
    algorithms: ['HS256'],
    issuer: settings.jwtIssuer,
    audience: settings.jwtAudience,
  });
}

function canonicalJson(value) {
  return JSON.stringify(value, Object.keys(value).sort());
}

function signRequest({ secret, timestamp, nonce, body }) {
  const bodyString = typeof body === 'string' ? body : canonicalJson(body || {});
  return crypto.createHmac('sha256', secret).update(`${timestamp}.${nonce}.${bodyString}`).digest('hex');
}

function verifyRequestSignature({ secret, timestamp, nonce, body, signature }) {
  const expected = signRequest({ secret, timestamp, nonce, body });
  const expectedBuf = Buffer.from(expected, 'utf8');
  const signatureBuf = Buffer.from(signature || '', 'utf8');
  if (expectedBuf.length !== signatureBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuf, signatureBuf);
}

function decodeMasterKey(masterKeyB64url) {
  const key = Buffer.from(masterKeyB64url, 'base64url');
  if (key.length !== 32) {
    throw new Error('Master encryption key must decode to 32 bytes');
  }
  return key;
}

function generateTenantDek() {
  return crypto.randomBytes(32).toString('base64url');
}

function aesGcmEncrypt(rawKey, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    tag: tag.toString('base64url'),
  };
}

function aesGcmDecrypt(rawKey, encrypted) {
  const iv = Buffer.from(encrypted.iv, 'base64url');
  const ciphertext = Buffer.from(encrypted.ciphertext, 'base64url');
  const tag = Buffer.from(encrypted.tag, 'base64url');
  const decipher = crypto.createDecipheriv('aes-256-gcm', rawKey, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

function encryptTenantDek(masterKeyB64url, tenantDekB64url) {
  const masterKey = decodeMasterKey(masterKeyB64url);
  const result = aesGcmEncrypt(masterKey, tenantDekB64url);
  return JSON.stringify(result);
}

function decryptTenantDek(masterKeyB64url, encryptedTenantDekJson) {
  const masterKey = decodeMasterKey(masterKeyB64url);
  const payload = JSON.parse(encryptedTenantDekJson);
  return aesGcmDecrypt(masterKey, payload);
}

function encryptWithMaster(masterKeyB64url, plaintext) {
  const masterKey = decodeMasterKey(masterKeyB64url);
  const result = aesGcmEncrypt(masterKey, plaintext);
  return JSON.stringify(result);
}

function decryptWithMaster(masterKeyB64url, encryptedJson) {
  const masterKey = decodeMasterKey(masterKeyB64url);
  const payload = JSON.parse(encryptedJson);
  return aesGcmDecrypt(masterKey, payload);
}

function encryptSecretValue(tenantDekB64url, plaintext) {
  const key = Buffer.from(tenantDekB64url, 'base64url');
  const encrypted = aesGcmEncrypt(key, plaintext);
  return {
    nonceB64: encrypted.iv,
    ciphertextB64: `${encrypted.ciphertext}.${encrypted.tag}`,
  };
}

function decryptSecretValue(tenantDekB64url, nonceB64, ciphertextB64) {
  const [ciphertext, tag] = ciphertextB64.split('.');
  const key = Buffer.from(tenantDekB64url, 'base64url');
  return aesGcmDecrypt(key, { iv: nonceB64, ciphertext, tag });
}

module.exports = {
  nowIso,
  nowMs,
  toDate,
  id,
  sha256,
  randomToken,
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
  signRequest,
  verifyRequestSignature,
  generateTenantDek,
  encryptTenantDek,
  decryptTenantDek,
  encryptWithMaster,
  decryptWithMaster,
  encryptSecretValue,
  decryptSecretValue,
};

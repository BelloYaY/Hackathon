const crypto = require('crypto');

function defaultMasterKey() {
  const digest = crypto.createHash('sha256').update('lucentid-master-key-default').digest();
  return digest.toString('base64url');
}

const settings = {
  appName: process.env.LUCENTID_APP_NAME || 'LucentID Core',
  env: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT || 3000),
  jwtIssuer: process.env.LUCENTID_JWT_ISSUER || 'lucentid-core',
  jwtAudience: process.env.LUCENTID_JWT_AUDIENCE || 'lucentid-enterprise',
  jwtSecret: process.env.LUCENTID_JWT_SECRET || 'lucentid-jwt-secret-change-me',
  accessTtlSeconds: Number(process.env.LUCENTID_ACCESS_TTL || 900),
  refreshTtlSeconds: Number(process.env.LUCENTID_REFRESH_TTL || 60 * 60 * 24 * 30),
  maxSessionSeconds: Number(process.env.LUCENTID_MAX_SESSION || 60 * 60 * 8),
  idleSessionSeconds: Number(process.env.LUCENTID_IDLE_SESSION || 60 * 30),
  requestSignatureSecret: process.env.LUCENTID_REQUEST_SIGNATURE_SECRET || 'lucentid-request-signature-secret',
  masterEncryptionKey: process.env.LUCENTID_MASTER_ENCRYPTION_KEY || defaultMasterKey(),
  bootstrapAdminKey: process.env.LUCENTID_BOOTSTRAP_ADMIN_KEY || 'lucentid-bootstrap-admin',
  mfaIssuer: process.env.LUCENTID_MFA_ISSUER || 'LucentID Core',
};

module.exports = { settings };

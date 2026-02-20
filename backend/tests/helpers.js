const request = require('supertest');
const speakeasy = require('speakeasy');

const { createApp } = require('../src/app');
const { database } = require('../src/database/db');
const { settings } = require('../src/config/settings');
const { signRequest } = require('../src/utils/security');

function testApp() {
  return createApp();
}

function resetDatabase() {
  database.exec('PRAGMA foreign_keys = OFF;');
  try {
    const rows = database.all(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
    `);

    for (const { name } of rows) {
      const quoted = `"${String(name).replace(/"/g, '""')}"`;
      database.run(`DELETE FROM ${quoted}`);
    }
  } finally {
    database.exec('PRAGMA foreign_keys = ON;');
  }
}

async function bootstrapTenant(app, tenantId = 'tenant-a', name = 'Tenant A') {
  const res = await request(app)
    .post('/api/v1/tenant/bootstrap')
    .set('x-bootstrap-key', settings.bootstrapAdminKey)
    .send({ tenant_id: tenantId, name, region: 'us', compliance_profile: 'standard' });
  return res;
}

async function registerUser(app, { tenantId, email, password, roles = ['user'] }) {
  return request(app)
    .post('/api/v1/auth/register')
    .set('x-tenant-id', tenantId)
    .send({ email, password, roles });
}

async function enrollMfa(app, { tenantId, email, password }) {
  const enroll = await request(app)
    .post('/api/v1/auth/mfa/enroll')
    .set('x-tenant-id', tenantId)
    .send({ email, password });

  const token = speakeasy.totp({ secret: enroll.body.secret, encoding: 'base32' });

  const verify = await request(app)
    .post('/api/v1/auth/mfa/verify')
    .set('x-tenant-id', tenantId)
    .send({
      email,
      password,
      factor_id: enroll.body.factorId,
      otp_code: token,
    });

  return { enroll, verify, secret: enroll.body.secret };
}

async function login(app, { tenantId, email, password, deviceId, deviceName = 'device', userAgent, otpCode }) {
  const req = request(app)
    .post('/api/v1/auth/login')
    .set('x-tenant-id', tenantId)
    .send({
      email,
      password,
      device_id: deviceId,
      device_name: deviceName,
      user_agent: userAgent || undefined,
      ip_address: '127.0.0.1',
      otp_code: otpCode,
    });
  if (userAgent) {
    req.set('user-agent', userAgent);
  }
  return req;
}

function signedHeaders(body = {}, nonce = `nonce-${Date.now()}`) {
  const timestamp = `${Date.now()}`;
  const signature = signRequest({
    secret: settings.requestSignatureSecret,
    timestamp,
    nonce,
    body,
  });
  return {
    'x-request-timestamp': timestamp,
    'x-request-nonce': nonce,
    'x-request-signature': signature,
  };
}

module.exports = {
  testApp,
  resetDatabase,
  bootstrapTenant,
  registerUser,
  enrollMfa,
  login,
  signedHeaders,
};

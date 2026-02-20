const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const speakeasy = require('speakeasy');

const {
  testApp,
  resetDatabase,
  bootstrapTenant,
  registerUser,
  enrollMfa,
  login,
  signedHeaders,
} = require('./helpers');

test('system controls: step-up endpoint elevates session auth strength', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-step-up');
  await registerUser(app, {
    tenantId: 'tenant-step-up',
    email: 'stepup@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const { secret } = await enrollMfa(app, {
    tenantId: 'tenant-step-up',
    email: 'stepup@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginOtp = speakeasy.totp({ secret, encoding: 'base32' });
  const loginRes = await login(app, {
    tenantId: 'tenant-step-up',
    email: 'stepup@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'step-up-device',
    otpCode: loginOtp,
  });
  assert.equal(loginRes.status, 200);

  const stepUpOtp = speakeasy.totp({ secret, encoding: 'base32' });
  const stepUpRes = await request(app)
    .post('/api/v1/auth/step-up')
    .set('x-tenant-id', 'tenant-step-up')
    .set('x-device-id', 'step-up-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .send({
      password: 'Str0ng!Password#1',
      otp_code: stepUpOtp,
    });
  assert.equal(stepUpRes.status, 200);
  assert.equal(stepUpRes.body.elevated, true);

  const meRes = await request(app)
    .get('/api/v1/auth/me')
    .set('x-tenant-id', 'tenant-step-up')
    .set('x-device-id', 'step-up-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`);
  assert.equal(meRes.status, 200);
  assert.equal(meRes.body.auth_strength, 3);
});

test('system controls: audit integrity endpoint returns valid chain status', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-audit-integrity');
  await registerUser(app, {
    tenantId: 'tenant-audit-integrity',
    email: 'audit-admin@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-audit-integrity',
    email: 'audit-admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'audit-admin-device',
  });
  assert.equal(loginRes.status, 200);

  const integrityRes = await request(app)
    .get('/api/v1/audit/integrity')
    .set('x-tenant-id', 'tenant-audit-integrity')
    .set('x-device-id', 'audit-admin-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`);

  assert.equal(integrityRes.status, 200);
  assert.equal(integrityRes.body.valid, true);
});

test('system controls: critical vault write requires step-up and allows after elevation', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-critical-vault');
  await registerUser(app, {
    tenantId: 'tenant-critical-vault',
    email: 'critical-admin@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const { secret } = await enrollMfa(app, {
    tenantId: 'tenant-critical-vault',
    email: 'critical-admin@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginOtp = speakeasy.totp({ secret, encoding: 'base32' });
  const loginRes = await login(app, {
    tenantId: 'tenant-critical-vault',
    email: 'critical-admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'critical-vault-device',
    otpCode: loginOtp,
  });
  assert.equal(loginRes.status, 200);

  const criticalBody = {
    name: 'critical-secret',
    value: 'critical-value',
    secret_class: 'critical',
  };
  const criticalHeaders = signedHeaders(criticalBody, 'nonce-critical-before-stepup');

  const blockedBeforeStepUp = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-critical-vault')
    .set('x-device-id', 'critical-vault-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set(criticalHeaders)
    .send(criticalBody);
  assert.equal(blockedBeforeStepUp.status, 403);

  const stepUpOtp = speakeasy.totp({ secret, encoding: 'base32' });
  const stepUpRes = await request(app)
    .post('/api/v1/auth/step-up')
    .set('x-tenant-id', 'tenant-critical-vault')
    .set('x-device-id', 'critical-vault-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .send({
      password: 'Str0ng!Password#1',
      otp_code: stepUpOtp,
    });
  assert.equal(stepUpRes.status, 200);

  const allowedBody = {
    name: 'critical-secret-elevated',
    value: 'critical-value-elevated',
    secret_class: 'critical',
  };
  const allowedHeaders = signedHeaders(allowedBody, 'nonce-critical-after-stepup');

  const allowedAfterStepUp = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-critical-vault')
    .set('x-device-id', 'critical-vault-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set(allowedHeaders)
    .send(allowedBody);
  assert.equal(allowedAfterStepUp.status, 201);
});

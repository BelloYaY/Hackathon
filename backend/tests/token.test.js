const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const {
  testApp,
  resetDatabase,
  bootstrapTenant,
  registerUser,
  login,
  signedHeaders,
} = require('./helpers');

test('token: refresh rotation issues new token pair', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-token');
  await registerUser(app, {
    tenantId: 'tenant-token',
    email: 'token@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-token',
    email: 'token@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'token-device',
  });
  assert.equal(loginRes.status, 200);

  const refreshRes = await request(app)
    .post('/api/v1/token/refresh')
    .set('x-tenant-id', 'tenant-token')
    .send({
      refresh_token: loginRes.body.refresh_token,
      device_id: 'token-device',
    });
  assert.equal(refreshRes.status, 200);
  assert.notEqual(refreshRes.body.access_token, loginRes.body.access_token);
  assert.notEqual(refreshRes.body.refresh_token, loginRes.body.refresh_token);
});

test('token: enterprise token validation API validates active token', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-validate');
  await registerUser(app, {
    tenantId: 'tenant-validate',
    email: 'validate@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-validate',
    email: 'validate@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'validate-device',
  });

  const body = {
    token: loginRes.body.access_token,
    device_id: 'validate-device',
  };

  const headers = signedHeaders(body, 'nonce-token-validate');
  const validateRes = await request(app)
    .post('/api/v1/token/validate')
    .set('x-tenant-id', 'tenant-validate')
    .set(headers)
    .send(body);

  assert.equal(validateRes.status, 200);
  assert.equal(validateRes.body.active, true);
  assert.equal(validateRes.body.tenant_id, 'tenant-validate');
});

test('token: revocation invalidates token validation', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-revoke-token');
  await registerUser(app, {
    tenantId: 'tenant-revoke-token',
    email: 'revoke@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-revoke-token',
    email: 'revoke@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'revoke-device',
  });

  const revokeRes = await request(app)
    .post('/api/v1/token/revoke')
    .set('x-tenant-id', 'tenant-revoke-token')
    .set('x-device-id', 'revoke-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .send({ token: loginRes.body.access_token, reason: 'manual_test' });
  assert.equal(revokeRes.status, 200);

  const validationBody = { token: loginRes.body.access_token, device_id: 'revoke-device' };
  const headers = signedHeaders(validationBody, 'nonce-token-revoked');
  const validateRes = await request(app)
    .post('/api/v1/token/validate')
    .set('x-tenant-id', 'tenant-revoke-token')
    .set(headers)
    .send(validationBody);

  assert.equal(validateRes.status, 200);
  assert.equal(validateRes.body.active, false);
});

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

test('vault: create, read, rotate secret with encryption-backed storage', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-vault');
  await registerUser(app, {
    tenantId: 'tenant-vault',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const adminLogin = await login(app, {
    tenantId: 'tenant-vault',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'vault-admin-device',
  });

  const createBody = {
    name: 'api-key',
    value: 'initial-secret-value',
    secret_class: 'standard',
  };
  const createHeaders = signedHeaders(createBody, 'nonce-vault-create');

  const createRes = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-vault')
    .set('x-device-id', 'vault-admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`)
    .set(createHeaders)
    .send(createBody);

  assert.equal(createRes.status, 201);
  assert.ok(createRes.body.id);
  assert.equal(createRes.body.version, 1);

  const readRes = await request(app)
    .get(`/api/v1/vault/secrets/${createRes.body.id}`)
    .set('x-tenant-id', 'tenant-vault')
    .set('x-device-id', 'vault-admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(readRes.status, 200);
  assert.equal(readRes.body.value, 'initial-secret-value');

  const rotateBody = { value: 'rotated-secret-value' };
  const rotateHeaders = signedHeaders(rotateBody, 'nonce-vault-rotate');

  const rotateRes = await request(app)
    .post(`/api/v1/vault/secrets/${createRes.body.id}/rotate`)
    .set('x-tenant-id', 'tenant-vault')
    .set('x-device-id', 'vault-admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`)
    .set(rotateHeaders)
    .send(rotateBody);

  assert.equal(rotateRes.status, 200);
  assert.equal(rotateRes.body.version, 2);

  const readRotated = await request(app)
    .get(`/api/v1/vault/secrets/${createRes.body.id}`)
    .set('x-tenant-id', 'tenant-vault')
    .set('x-device-id', 'vault-admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(readRotated.status, 200);
  assert.equal(readRotated.body.value, 'rotated-secret-value');
});

test('vault: replay protection blocks nonce reuse on signed requests', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-vault-replay');
  await registerUser(app, {
    tenantId: 'tenant-vault-replay',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-vault-replay',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'vault-replay-device',
  });

  const body = {
    name: 'nonce-test',
    value: 'sensitive-value',
    secret_class: 'standard',
  };

  const replayHeaders = signedHeaders(body, 'reused-nonce-1');

  const first = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-vault-replay')
    .set('x-device-id', 'vault-replay-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set(replayHeaders)
    .send(body);

  assert.equal(first.status, 201);

  const second = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-vault-replay')
    .set('x-device-id', 'vault-replay-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set(replayHeaders)
    .send(body);

  assert.equal(second.status, 409);
});

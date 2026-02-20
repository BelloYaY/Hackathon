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

test('tenant isolation: cross-tenant token usage is denied', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-a', 'Tenant A');
  await bootstrapTenant(app, 'tenant-b', 'Tenant B');

  await registerUser(app, {
    tenantId: 'tenant-a',
    email: 'admin@a.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const loginA = await login(app, {
    tenantId: 'tenant-a',
    email: 'admin@a.com',
    password: 'Str0ng!Password#1',
    deviceId: 'tenant-a-device',
  });

  const crossUse = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-b')
    .set('x-device-id', 'tenant-a-device')
    .set('authorization', `Bearer ${loginA.body.access_token}`);

  assert.equal(crossUse.status, 403);
});

test('tenant isolation: cross-tenant secret access is blocked', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-x', 'Tenant X');
  await bootstrapTenant(app, 'tenant-y', 'Tenant Y');

  await registerUser(app, {
    tenantId: 'tenant-x',
    email: 'admin@x.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const loginX = await login(app, {
    tenantId: 'tenant-x',
    email: 'admin@x.com',
    password: 'Str0ng!Password#1',
    deviceId: 'tenant-x-device',
  });

  const createBody = { name: 'tenant-x-secret', value: 'x-value', secret_class: 'standard' };
  const headers = signedHeaders(createBody, 'nonce-tenant-x-secret');

  const createSecret = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-x')
    .set('x-device-id', 'tenant-x-device')
    .set('authorization', `Bearer ${loginX.body.access_token}`)
    .set(headers)
    .send(createBody);

  assert.equal(createSecret.status, 201);

  const crossRead = await request(app)
    .get(`/api/v1/vault/secrets/${createSecret.body.id}`)
    .set('x-tenant-id', 'tenant-y')
    .set('x-device-id', 'tenant-x-device')
    .set('authorization', `Bearer ${loginX.body.access_token}`);

  assert.equal(crossRead.status, 403);
});

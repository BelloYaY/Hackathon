const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { testApp, resetDatabase, bootstrapTenant, registerUser, login } = require('./helpers');

test('trust: trust endpoint returns computed score and risk', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-trust');
  await registerUser(app, {
    tenantId: 'tenant-trust',
    email: 'trust@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-trust',
    email: 'trust@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'trust-device',
  });

  const trustRes = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-trust')
    .set('x-device-id', 'trust-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set('x-forwarded-for', '127.0.0.1');

  assert.equal(trustRes.status, 200);
  assert.ok(Number.isInteger(trustRes.body.trust_score));
  assert.ok(['low', 'guarded', 'elevated', 'high', 'critical'].includes(trustRes.body.risk_level));
});

test('trust: IP drift triggers hijack defense block', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-trust-drift');
  await registerUser(app, {
    tenantId: 'tenant-trust-drift',
    email: 'drift@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-trust-drift',
    email: 'drift@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'drift-device',
  });

  const baseline = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-trust-drift')
    .set('x-device-id', 'drift-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set('x-forwarded-for', '127.0.0.1');

  const drifted = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-trust-drift')
    .set('x-device-id', 'drift-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set('x-forwarded-for', '203.0.113.77');

  assert.equal(baseline.status, 200);
  assert.equal(drifted.status, 403);
});

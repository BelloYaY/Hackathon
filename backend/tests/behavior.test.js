const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { database } = require('../src/database/db');
const { testApp, resetDatabase, bootstrapTenant, registerUser, login } = require('./helpers');

test('behavior: anomaly events are captured for suspicious context shifts', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-behavior');
  await registerUser(app, {
    tenantId: 'tenant-behavior',
    email: 'behavior@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-behavior',
    email: 'behavior@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'behavior-device',
    userAgent: 'baseline-agent',
  });
  assert.equal(loginRes.status, 200);

  const suspicious = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-behavior')
    .set('x-device-id', 'behavior-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set('user-agent', 'changed-agent')
    .set('x-forwarded-for', '198.51.100.10');

  assert.ok([200, 403].includes(suspicious.status));

  const count = database.get(
    `SELECT COUNT(*) AS count FROM behavior_events WHERE tenant_id = :tenantId`,
    { tenantId: 'tenant-behavior' }
  ).count;
  assert.ok(count >= 1);
});

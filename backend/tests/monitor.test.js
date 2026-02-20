const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const {
  testApp,
  resetDatabase,
  bootstrapTenant,
  registerUser,
  login,
} = require('./helpers');

test('monitoring: admin can retrieve security overview and event feeds', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-monitor');
  await registerUser(app, {
    tenantId: 'tenant-monitor',
    email: 'admin@monitor.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const adminLogin = await login(app, {
    tenantId: 'tenant-monitor',
    email: 'admin@monitor.com',
    password: 'Str0ng!Password#1',
    deviceId: 'monitor-device',
  });
  assert.equal(adminLogin.status, 200);

  const overview = await request(app)
    .get('/api/v1/monitor/security-overview')
    .set('x-tenant-id', 'tenant-monitor')
    .set('x-device-id', 'monitor-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(overview.status, 200);
  assert.equal(overview.body.tenant_id, 'tenant-monitor');
  assert.ok(Number.isInteger(overview.body.active_sessions));

  const auditEvents = await request(app)
    .get('/api/v1/audit/events?limit=20')
    .set('x-tenant-id', 'tenant-monitor')
    .set('x-device-id', 'monitor-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(auditEvents.status, 200);
  assert.ok(Array.isArray(auditEvents.body));

  const riskEvents = await request(app)
    .get('/api/v1/monitor/risk-events?limit=20')
    .set('x-tenant-id', 'tenant-monitor')
    .set('x-device-id', 'monitor-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(riskEvents.status, 200);
  assert.ok(Array.isArray(riskEvents.body));

  const behaviorEvents = await request(app)
    .get('/api/v1/monitor/behavior-events?limit=20')
    .set('x-tenant-id', 'tenant-monitor')
    .set('x-device-id', 'monitor-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(behaviorEvents.status, 200);
  assert.ok(Array.isArray(behaviorEvents.body));
});

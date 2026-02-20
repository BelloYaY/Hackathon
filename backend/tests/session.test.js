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

test('session: active session introspection works', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-session');
  await registerUser(app, {
    tenantId: 'tenant-session',
    email: 'session@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-session',
    email: 'session@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'session-device',
  });

  const me = await request(app)
    .get('/api/v1/session/me')
    .set('x-tenant-id', 'tenant-session')
    .set('x-device-id', 'session-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`);

  assert.equal(me.status, 200);
  assert.equal(me.body.state, 'active');
});

test('session: lock and revoke controls are enforced', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-session-admin');
  await registerUser(app, {
    tenantId: 'tenant-session-admin',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const adminLogin = await login(app, {
    tenantId: 'tenant-session-admin',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'admin-session-device',
  });
  const adminControlLogin = await login(app, {
    tenantId: 'tenant-session-admin',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'admin-control-device',
  });

  const sessionId = adminLogin.body.session_id;

  const lock = await request(app)
    .post(`/api/v1/session/${sessionId}/lock`)
    .set('x-tenant-id', 'tenant-session-admin')
    .set('x-device-id', 'admin-control-device')
    .set('authorization', `Bearer ${adminControlLogin.body.access_token}`)
    .send({ reason: 'test-lock' });

  assert.equal(lock.status, 200);
  assert.equal(lock.body.state, 'locked');

  const meWhileLocked = await request(app)
    .get('/api/v1/session/me')
    .set('x-tenant-id', 'tenant-session-admin')
    .set('x-device-id', 'admin-session-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(meWhileLocked.status, 403);

  const unlock = await request(app)
    .post(`/api/v1/session/${sessionId}/unlock`)
    .set('x-tenant-id', 'tenant-session-admin')
    .set('x-device-id', 'admin-control-device')
    .set('authorization', `Bearer ${adminControlLogin.body.access_token}`)
    .send({ reason: 'test-unlock' });

  assert.equal(unlock.status, 200);
  assert.equal(unlock.body.state, 'active');

  const meAfterUnlock = await request(app)
    .get('/api/v1/session/me')
    .set('x-tenant-id', 'tenant-session-admin')
    .set('x-device-id', 'admin-session-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`);

  assert.equal(meAfterUnlock.status, 200);

  const revoke = await request(app)
    .post(`/api/v1/session/${sessionId}/revoke`)
    .set('x-tenant-id', 'tenant-session-admin')
    .set('x-device-id', 'admin-control-device')
    .set('authorization', `Bearer ${adminControlLogin.body.access_token}`)
    .send({ reason: 'test-revoke' });

  assert.equal(revoke.status, 200);
  assert.equal(revoke.body.state, 'revoked');
});

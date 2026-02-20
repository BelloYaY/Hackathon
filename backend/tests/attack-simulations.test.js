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

test('attack simulation: token theft is blocked by token-device binding', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-attack-token');
  await registerUser(app, {
    tenantId: 'tenant-attack-token',
    email: 'token@attack.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-attack-token',
    email: 'token@attack.com',
    password: 'Str0ng!Password#1',
    deviceId: 'legit-device',
  });

  const stolenUse = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-attack-token')
    .set('x-device-id', 'attacker-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`);

  assert.equal(stolenUse.status, 403);
});

test('attack simulation: session hijacking is detected and blocked', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-attack-session');
  await registerUser(app, {
    tenantId: 'tenant-attack-session',
    email: 'session@attack.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-attack-session',
    email: 'session@attack.com',
    password: 'Str0ng!Password#1',
    deviceId: 'session-device',
  });

  const hijack = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-attack-session')
    .set('x-device-id', 'session-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set('x-forwarded-for', '203.0.113.200');

  assert.equal(hijack.status, 403);
});

test('attack simulation: device spoofing is detected and blocked', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-attack-device');
  await registerUser(app, {
    tenantId: 'tenant-attack-device',
    email: 'device@attack.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-attack-device',
    email: 'device@attack.com',
    password: 'Str0ng!Password#1',
    deviceId: 'trusted-device',
    userAgent: 'trusted-agent',
  });

  const spoof = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-attack-device')
    .set('x-device-id', 'trusted-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set('user-agent', 'spoofed-agent')
    .set('x-forwarded-for', '10.10.10.10');

  assert.equal(spoof.status, 403);
});

test('attack simulation: replay attack is blocked by nonce tracking', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-attack-replay');
  await registerUser(app, {
    tenantId: 'tenant-attack-replay',
    email: 'admin@attack.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-attack-replay',
    email: 'admin@attack.com',
    password: 'Str0ng!Password#1',
    deviceId: 'replay-device',
  });

  const body = { name: 'replay-secret', value: 'x', secret_class: 'standard' };
  const headers = signedHeaders(body, 'attack-replay-nonce');

  const first = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-attack-replay')
    .set('x-device-id', 'replay-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set(headers)
    .send(body);
  assert.equal(first.status, 201);

  const second = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-attack-replay')
    .set('x-device-id', 'replay-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .set(headers)
    .send(body);

  assert.equal(second.status, 409);
});

test('attack simulation: privilege escalation is blocked for non-admin', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-attack-priv');
  await registerUser(app, {
    tenantId: 'tenant-attack-priv',
    email: 'user@attack.com',
    password: 'Str0ng!Password#1',
    roles: ['user'],
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-attack-priv',
    email: 'user@attack.com',
    password: 'Str0ng!Password#1',
    deviceId: 'user-attack-device',
  });

  const escalate = await request(app)
    .post(`/api/v1/session/${loginRes.body.session_id}/lock`)
    .set('x-tenant-id', 'tenant-attack-priv')
    .set('x-device-id', 'user-attack-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .send({ reason: 'priv-escalation-attempt' });

  assert.equal(escalate.status, 403);
});

test('attack simulation: cross-tenant access is blocked', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-attack-a', 'Tenant Attack A');
  await bootstrapTenant(app, 'tenant-attack-b', 'Tenant Attack B');

  await registerUser(app, {
    tenantId: 'tenant-attack-a',
    email: 'a@attack.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const loginA = await login(app, {
    tenantId: 'tenant-attack-a',
    email: 'a@attack.com',
    password: 'Str0ng!Password#1',
    deviceId: 'tenant-a-device',
  });

  const cross = await request(app)
    .get('/api/v1/trust/me')
    .set('x-tenant-id', 'tenant-attack-b')
    .set('x-device-id', 'tenant-a-device')
    .set('authorization', `Bearer ${loginA.body.access_token}`);

  assert.equal(cross.status, 403);
});

test('attack simulation: behavior anomaly from repeated failures triggers lockout', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-attack-behavior');
  await registerUser(app, {
    tenantId: 'tenant-attack-behavior',
    email: 'behavior@attack.com',
    password: 'Str0ng!Password#1',
  });

  for (let i = 0; i < 6; i += 1) {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('x-tenant-id', 'tenant-attack-behavior')
      .send({
        email: 'behavior@attack.com',
        password: 'Wrong#Password!999',
        device_id: `attack-behavior-${i}`,
      });

    if (i < 5) {
      assert.equal(res.status, 401);
    } else {
      assert.equal(res.status, 403);
    }
  }
});

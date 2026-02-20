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

test('policy: privilege escalation is blocked for non-admin users', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-policy-priv');
  await registerUser(app, {
    tenantId: 'tenant-policy-priv',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['user'],
  });

  const userLogin = await login(app, {
    tenantId: 'tenant-policy-priv',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'policy-user-device',
  });

  const attempt = await request(app)
    .post(`/api/v1/session/${userLogin.body.session_id}/lock`)
    .set('x-tenant-id', 'tenant-policy-priv')
    .set('x-device-id', 'policy-user-device')
    .set('authorization', `Bearer ${userLogin.body.access_token}`)
    .send({ reason: 'unauthorized-lock' });

  assert.equal(attempt.status, 403);
});

test('policy: dynamic deny rule enforces access restrictions', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-policy-dynamic');
  await registerUser(app, {
    tenantId: 'tenant-policy-dynamic',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });
  await registerUser(app, {
    tenantId: 'tenant-policy-dynamic',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['user'],
  });

  const adminLogin = await login(app, {
    tenantId: 'tenant-policy-dynamic',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'policy-admin-device',
  });
  const userLogin = await login(app, {
    tenantId: 'tenant-policy-dynamic',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'policy-user-device',
  });

  const policyBody = {
    name: 'deny_vault_read_for_users',
    priority: 10,
    rules: {
      rules: [
        {
          effect: 'deny',
          action: 'vault:read',
          resource: 'secret',
          requiredRoles: ['user'],
        },
      ],
    },
  };
  const policyHeaders = signedHeaders(policyBody, 'nonce-policy-create');

  const createPolicy = await request(app)
    .post('/api/v1/policy')
    .set('x-tenant-id', 'tenant-policy-dynamic')
    .set('x-device-id', 'policy-admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`)
    .set(policyHeaders)
    .send(policyBody);
  assert.equal(createPolicy.status, 201);

  const secretBody = {
    name: 'db-password',
    value: 'super-secret-value',
    secret_class: 'standard',
  };
  const secretHeaders = signedHeaders(secretBody, 'nonce-secret-create');

  const createSecret = await request(app)
    .post('/api/v1/vault/secrets')
    .set('x-tenant-id', 'tenant-policy-dynamic')
    .set('x-device-id', 'policy-admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`)
    .set(secretHeaders)
    .send(secretBody);
  assert.equal(createSecret.status, 201);

  const readSecret = await request(app)
    .get(`/api/v1/vault/secrets/${createSecret.body.id}`)
    .set('x-tenant-id', 'tenant-policy-dynamic')
    .set('x-device-id', 'policy-user-device')
    .set('authorization', `Bearer ${userLogin.body.access_token}`);

  assert.equal(readSecret.status, 403);
});

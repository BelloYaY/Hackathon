const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('crypto');

const {
  testApp,
  resetDatabase,
  bootstrapTenant,
  registerUser,
  login,
} = require('./helpers');

test('device: approve and revoke device through admin controls', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-device');
  await registerUser(app, {
    tenantId: 'tenant-device',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });
  await registerUser(app, {
    tenantId: 'tenant-device',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
  });

  const adminLogin = await login(app, {
    tenantId: 'tenant-device',
    email: 'admin@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'admin-device',
  });
  assert.equal(adminLogin.status, 200);

  await login(app, {
    tenantId: 'tenant-device',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'user-device',
  });

  const approve = await request(app)
    .post('/api/v1/device/user-device/approve')
    .set('x-tenant-id', 'tenant-device')
    .set('x-device-id', 'admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`)
    .send({});
  assert.equal(approve.status, 200);
  assert.equal(approve.body.is_approved, true);

  const revoke = await request(app)
    .post('/api/v1/device/user-device/revoke')
    .set('x-tenant-id', 'tenant-device')
    .set('x-device-id', 'admin-device')
    .set('authorization', `Bearer ${adminLogin.body.access_token}`)
    .send({ reason: 'compromise' });
  assert.equal(revoke.status, 200);
  assert.equal(revoke.body.trust_tier, 'revoked');
});

test('device: hardware-bound challenge/attestation flow', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-hw');
  await registerUser(app, {
    tenantId: 'tenant-hw',
    email: 'hw@corp.com',
    password: 'Str0ng!Password#1',
  });

  const loginRes = await login(app, {
    tenantId: 'tenant-hw',
    email: 'hw@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'hw-device',
  });
  assert.equal(loginRes.status, 200);

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

  const bind = await request(app)
    .post('/api/v1/device/hw-device/hardware-key')
    .set('x-tenant-id', 'tenant-hw')
    .set('x-device-id', 'hw-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .send({ public_key_pem: publicKeyPem, attestation_level: 'attested' });
  assert.equal(bind.status, 200);
  assert.equal(bind.body.is_hardware_bound, true);

  const challenge = await request(app)
    .post('/api/v1/device/hw-device/challenge')
    .set('x-tenant-id', 'tenant-hw')
    .set('x-device-id', 'hw-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .send({});
  assert.equal(challenge.status, 201);

  const signature = crypto.sign(null, Buffer.from(challenge.body.nonce, 'utf8'), privateKey);

  const attest = await request(app)
    .post('/api/v1/device/hw-device/attest')
    .set('x-tenant-id', 'tenant-hw')
    .set('x-device-id', 'hw-device')
    .set('authorization', `Bearer ${loginRes.body.access_token}`)
    .send({ challenge_id: challenge.body.challenge_id, signature_b64: signature.toString('base64') });
  assert.equal(attest.status, 200);
  assert.equal(attest.body.is_hardware_bound, true);
});

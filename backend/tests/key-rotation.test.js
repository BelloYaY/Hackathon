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

function decodeHeaderKid(jwtToken) {
  const [header] = jwtToken.split('.');
  const decoded = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
  return decoded.kid;
}

test('token signing keys: JWKS exposes active key and rotation updates kid', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-keys');
  await registerUser(app, {
    tenantId: 'tenant-keys',
    email: 'admin@keys.com',
    password: 'Str0ng!Password#1',
    roles: ['admin'],
  });

  const login1 = await login(app, {
    tenantId: 'tenant-keys',
    email: 'admin@keys.com',
    password: 'Str0ng!Password#1',
    deviceId: 'keys-device',
  });
  assert.equal(login1.status, 200);

  const kid1 = decodeHeaderKid(login1.body.access_token);
  assert.ok(kid1);

  const jwks1 = await request(app).get('/api/v1/token/jwks');
  assert.equal(jwks1.status, 200);
  assert.ok(Array.isArray(jwks1.body.keys));
  assert.ok(jwks1.body.keys.some((k) => k.kid === kid1));

  const rotateBody = {};
  const rotateHeaders = signedHeaders(rotateBody, 'nonce-key-rotate');
  const rotate = await request(app)
    .post('/api/v1/token/keys/rotate')
    .set('x-tenant-id', 'tenant-keys')
    .set('x-device-id', 'keys-device')
    .set('authorization', `Bearer ${login1.body.access_token}`)
    .set(rotateHeaders)
    .send(rotateBody);

  assert.equal(rotate.status, 200);
  assert.equal(rotate.body.rotated, true);
  assert.ok(rotate.body.kid);

  const login2 = await login(app, {
    tenantId: 'tenant-keys',
    email: 'admin@keys.com',
    password: 'Str0ng!Password#1',
    deviceId: 'keys-device',
  });
  assert.equal(login2.status, 200);

  const kid2 = decodeHeaderKid(login2.body.access_token);
  assert.ok(kid2);
  assert.notEqual(kid1, kid2);

  const validateBodyOld = { token: login1.body.access_token, device_id: 'keys-device' };
  const validateHeadersOld = signedHeaders(validateBodyOld, 'nonce-key-validate-old');
  const oldTokenValidation = await request(app)
    .post('/api/v1/token/validate')
    .set('x-tenant-id', 'tenant-keys')
    .set(validateHeadersOld)
    .send(validateBodyOld);
  assert.equal(oldTokenValidation.status, 200);
  assert.equal(oldTokenValidation.body.active, true);

  const jwks2 = await request(app).get('/api/v1/token/jwks');
  assert.equal(jwks2.status, 200);
  assert.ok(jwks2.body.keys.some((k) => k.kid === kid1));
  assert.ok(jwks2.body.keys.some((k) => k.kid === kid2));
});

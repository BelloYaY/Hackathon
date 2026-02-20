const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const speakeasy = require('speakeasy');

const {
  testApp,
  resetDatabase,
  bootstrapTenant,
  registerUser,
  enrollMfa,
  login,
} = require('./helpers');

test('authentication: register and login with password', async () => {
  resetDatabase();
  const app = testApp();

  const tenantRes = await bootstrapTenant(app, 'tenant-auth');
  assert.equal(tenantRes.status, 201);

  const registerRes = await registerUser(app, {
    tenantId: 'tenant-auth',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
  });
  assert.equal(registerRes.status, 201);

  const loginRes = await login(app, {
    tenantId: 'tenant-auth',
    email: 'user@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'device-auth-1',
  });
  assert.equal(loginRes.status, 200);
  assert.ok(loginRes.body.access_token);
  assert.ok(loginRes.body.refresh_token);
  assert.ok(loginRes.body.session_id);
});

test('authentication: weak password is rejected by policy', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-password-policy');

  const registerRes = await registerUser(app, {
    tenantId: 'tenant-password-policy',
    email: 'weak@corp.com',
    password: 'weakpass',
  });

  assert.equal(registerRes.status, 400);
});

test('authentication: MFA required when factor is verified', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-mfa');
  await registerUser(app, {
    tenantId: 'tenant-mfa',
    email: 'mfa@corp.com',
    password: 'Str0ng!Password#1',
  });

  const { secret } = await enrollMfa(app, {
    tenantId: 'tenant-mfa',
    email: 'mfa@corp.com',
    password: 'Str0ng!Password#1',
  });

  const noOtpLogin = await login(app, {
    tenantId: 'tenant-mfa',
    email: 'mfa@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'device-mfa-1',
  });
  assert.equal(noOtpLogin.status, 403);

  const otp = speakeasy.totp({ secret, encoding: 'base32' });
  const otpLogin = await login(app, {
    tenantId: 'tenant-mfa',
    email: 'mfa@corp.com',
    password: 'Str0ng!Password#1',
    deviceId: 'device-mfa-1',
    otpCode: otp,
  });
  assert.equal(otpLogin.status, 200);
  assert.ok(otpLogin.body.access_token);
});

test('authentication: adaptive lockout on repeated failures', async () => {
  resetDatabase();
  const app = testApp();

  await bootstrapTenant(app, 'tenant-lockout');
  await registerUser(app, {
    tenantId: 'tenant-lockout',
    email: 'lock@corp.com',
    password: 'Str0ng!Password#1',
  });

  for (let i = 0; i < 6; i += 1) {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('x-tenant-id', 'tenant-lockout')
      .send({
        email: 'lock@corp.com',
        password: 'wrong-password',
        device_id: `device-lock-${i}`,
      });

    if (i < 5) {
      assert.equal(res.status, 401);
    } else {
      assert.equal(res.status, 403);
    }
  }
});

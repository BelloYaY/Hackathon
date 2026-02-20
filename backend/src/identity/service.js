const speakeasy = require('speakeasy');

const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { settings } = require('../config/settings');
const { ConflictError, ForbiddenError, NotFoundError, UnauthorizedError, ValidationError } = require('../core/errors');
const { id, nowIso, hashPassword, verifyPassword } = require('../utils/security');

class IdentityService {
  constructor() {
    this.passwordPepper = 'lucentid-password-pepper';
  }

  validatePasswordPolicy(password) {
    if (password.length < 12) {
      throw new ValidationError('Password must be at least 12 characters');
    }
    const checks = [/[A-Z]/, /[a-z]/, /\d/, /[^A-Za-z0-9]/];
    if (!checks.every((regex) => regex.test(password))) {
      throw new ValidationError('Password must include upper, lower, number, and symbol');
    }
  }

  registerUser({ tenantId, email, password, roles = ['user'] }) {
    this.validatePasswordPolicy(password);
    const normalizedEmail = email.trim().toLowerCase();
    const existing = database.get(`SELECT id FROM users WHERE tenant_id = :tenantId AND email = :email`, {
      tenantId,
      email: normalizedEmail,
    });
    if (existing) {
      throw new ConflictError('User already exists');
    }

    const userId = id('usr');
    database.run(
      `INSERT INTO users (id, tenant_id, email, password_hash, roles_json, status, assurance_level, failed_login_count, created_at)
       VALUES (:id, :tenantId, :email, :passwordHash, :rolesJson, 'active', 1, 0, :createdAt)`,
      {
        id: userId,
        tenantId,
        email: normalizedEmail,
        passwordHash: hashPassword(password, this.passwordPepper),
        rolesJson: JSON.stringify(roles),
        createdAt: nowIso(),
      }
    );

    auditService.log({
      tenantId,
      actorId: userId,
      eventType: 'identity',
      actionName: 'register',
      targetId: normalizedEmail,
      decision: 'allow',
      metadata: { roles },
    });

    return { userId, email: normalizedEmail, tenantId };
  }

  getUserByEmail({ tenantId, email }) {
    return database.get(`SELECT * FROM users WHERE tenant_id = :tenantId AND email = :email`, {
      tenantId,
      email: email.trim().toLowerCase(),
    });
  }

  getUserById({ tenantId, userId }) {
    const user = database.get(`SELECT * FROM users WHERE tenant_id = :tenantId AND id = :userId`, {
      tenantId,
      userId,
    });
    if (!user) {
      throw new NotFoundError('User not found');
    }
    return user;
  }

  createTotpFactor({ tenantId, userId, email }) {
    const factorId = id('mfa');
    const secret = speakeasy.generateSecret({
      name: `${settings.mfaIssuer}:${email}`,
      issuer: settings.mfaIssuer,
      length: 32,
    });

    database.run(
      `INSERT INTO mfa_factors (id, tenant_id, user_id, factor_type, secret, is_verified, created_at)
       VALUES (:id, :tenantId, :userId, 'totp', :secret, 0, :createdAt)`,
      {
        id: factorId,
        tenantId,
        userId,
        secret: secret.base32,
        createdAt: nowIso(),
      }
    );

    auditService.log({
      tenantId,
      actorId: userId,
      eventType: 'mfa',
      actionName: 'enroll',
      targetId: factorId,
      decision: 'allow',
      metadata: {},
    });

    return {
      factorId,
      secret: secret.base32,
      provisioningUri: secret.otpauth_url,
    };
  }

  verifyTotpFactor({ tenantId, userId, factorId, otpCode }) {
    const factor = database.get(
      `SELECT * FROM mfa_factors WHERE tenant_id = :tenantId AND user_id = :userId AND id = :factorId`,
      {
        tenantId,
        userId,
        factorId,
      }
    );
    if (!factor) {
      throw new NotFoundError('MFA factor not found');
    }

    const valid = speakeasy.totp.verify({
      secret: factor.secret,
      encoding: 'base32',
      token: otpCode,
      window: 1,
    });

    if (valid) {
      database.run(
        `UPDATE mfa_factors SET is_verified = 1 WHERE id = :factorId`,
        { factorId }
      );
    }

    auditService.log({
      tenantId,
      actorId: userId,
      eventType: 'mfa',
      actionName: 'verify',
      targetId: factorId,
      decision: valid ? 'allow' : 'deny',
      metadata: valid ? {} : { reason: 'invalid_otp' },
    });

    return valid;
  }

  hasVerifiedMfa({ tenantId, userId }) {
    const row = database.get(
      `SELECT id FROM mfa_factors WHERE tenant_id = :tenantId AND user_id = :userId AND is_verified = 1 LIMIT 1`,
      { tenantId, userId }
    );
    return !!row;
  }

  verifyUserOtp({ tenantId, userId, otpCode }) {
    if (!otpCode) {
      return false;
    }
    const factors = database.all(
      `SELECT secret FROM mfa_factors WHERE tenant_id = :tenantId AND user_id = :userId AND is_verified = 1`,
      { tenantId, userId }
    );
    for (const factor of factors) {
      const valid = speakeasy.totp.verify({
        secret: factor.secret,
        encoding: 'base32',
        token: otpCode,
        window: 1,
      });
      if (valid) {
        return true;
      }
    }
    return false;
  }

  recordAuthAttempt({ tenantId, userId = null, email, success, ipAddress, reason }) {
    const normalizedEmail = email.trim().toLowerCase();
    const tenantExists = database.get(`SELECT id FROM tenants WHERE id = :tenantId`, { tenantId });
    if (!tenantExists) {
      return;
    }

    try {
      database.run(
        `INSERT INTO auth_attempts (id, tenant_id, user_id, email, success, ip_address, reason, created_at)
         VALUES (:id, :tenantId, :userId, :email, :success, :ipAddress, :reason, :createdAt)`,
        {
          id: id('att'),
          tenantId,
          userId,
          email: normalizedEmail,
          success: success ? 1 : 0,
          ipAddress,
          reason,
          createdAt: nowIso(),
        }
      );
    } catch {
      // Auth logging should not break authentication flow.
    }
  }

  recentFailedAttempts({ tenantId, email }) {
    const rows = database.all(
      `SELECT id FROM auth_attempts
       WHERE tenant_id = :tenantId AND email = :email AND success = 0
       AND datetime(created_at) >= datetime('now', '-10 minutes')`,
      { tenantId, email: email.trim().toLowerCase() }
    );
    return rows.length;
  }

  authenticatePassword({ tenantId, email, password, ipAddress }) {
    const normalizedEmail = email.trim().toLowerCase();
    const user = this.getUserByEmail({ tenantId, email: normalizedEmail });
    if (!user) {
      this.recordAuthAttempt({
        tenantId,
        userId: null,
        email: normalizedEmail,
        success: false,
        ipAddress,
        reason: 'unknown_user',
      });
      throw new UnauthorizedError('Invalid credentials');
    }

    if (user.status !== 'active') {
      this.recordAuthAttempt({
        tenantId,
        userId: user.id,
        email: normalizedEmail,
        success: false,
        ipAddress,
        reason: 'user_not_active',
      });
      throw new ForbiddenError('User account is not active');
    }

    const recentFailures = this.recentFailedAttempts({ tenantId, email: normalizedEmail });
    if (recentFailures >= 5) {
      database.run(`UPDATE users SET status = 'locked' WHERE id = :userId`, { userId: user.id });
      this.recordAuthAttempt({
        tenantId,
        userId: user.id,
        email: normalizedEmail,
        success: false,
        ipAddress,
        reason: 'adaptive_lockout',
      });
      throw new ForbiddenError('Account temporarily locked');
    }

    if (!verifyPassword(password, user.password_hash, this.passwordPepper)) {
      database.run(
        `UPDATE users SET failed_login_count = failed_login_count + 1, last_failed_login_at = :ts WHERE id = :userId`,
        { ts: nowIso(), userId: user.id }
      );
      this.recordAuthAttempt({
        tenantId,
        userId: user.id,
        email: normalizedEmail,
        success: false,
        ipAddress,
        reason: 'invalid_password',
      });
      auditService.log({
        tenantId,
        actorId: user.id,
        eventType: 'auth',
        actionName: 'login',
        targetId: normalizedEmail,
        decision: 'deny',
        metadata: { reason: 'invalid_password' },
      });
      throw new UnauthorizedError('Invalid credentials');
    }

    database.run(
      `UPDATE users SET failed_login_count = 0 WHERE id = :userId`,
      { userId: user.id }
    );
    this.recordAuthAttempt({
      tenantId,
      userId: user.id,
      email: normalizedEmail,
      success: true,
      ipAddress,
      reason: 'success',
    });

    return user;
  }
}

const identityService = new IdentityService();

module.exports = {
  identityService,
};

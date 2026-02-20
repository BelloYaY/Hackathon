const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');
const { identityService } = require('../identity/service');
const { deviceService } = require('../device/service');
const { trustService } = require('../trust/service');
const { riskService } = require('../risk/service');
const { sessionService } = require('../session/service');
const { tokenService } = require('../token/service');
const { behaviorService } = require('../behavior/service');
const { database } = require('../database/db');
const { parseRoles } = require('../utils/context');
const { normalizeIp } = require('../utils/context');
const { ValidationError, ForbiddenError } = require('../core/errors');
const { auditService } = require('../audit/service');

const authRouter = express.Router();

authRouter.post('/register', requireTenant, (req, res, next) => {
  try {
    const { email, password, roles = ['user'] } = req.body || {};
    if (!email || !password) {
      throw new ValidationError('email and password are required');
    }
    const result = identityService.registerUser({
      tenantId: req.tenantId,
      email,
      password,
      roles,
    });
    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
});

authRouter.get('/me', requireTenant, requireAuth({ action: 'session:read', resource: 'identity' }), (req, res, next) => {
  try {
    const user = database.get(`SELECT * FROM users WHERE tenant_id = :tenantId AND id = :userId`, {
      tenantId: req.tenantId,
      userId: req.securityContext.userId,
    });
    if (!user) {
      throw new ForbiddenError('User not found');
    }

    res.json({
      id: user.id,
      email: user.email,
      tenant_id: req.tenantId,
      roles: parseRoles(user.roles_json),
      session_id: req.securityContext.sessionId,
      trust_score: req.securityContext.trustScore,
      risk_level: req.securityContext.riskLevel,
      auth_strength: req.securityContext.authStrength,
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/mfa/enroll', requireTenant, (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      throw new ValidationError('email and password are required');
    }
    const user = identityService.authenticatePassword({
      tenantId: req.tenantId,
      email,
      password,
      ipAddress: req.ip || '0.0.0.0',
    });
    const factor = identityService.createTotpFactor({
      tenantId: req.tenantId,
      userId: user.id,
      email: user.email,
    });
    res.status(201).json(factor);
  } catch (err) {
    next(err);
  }
});

authRouter.post('/mfa/verify', requireTenant, (req, res, next) => {
  try {
    const { email, password, factor_id: factorId, otp_code: otpCode } = req.body || {};
    if (!email || !password || !factorId || !otpCode) {
      throw new ValidationError('email, password, factor_id, and otp_code are required');
    }
    const user = identityService.authenticatePassword({
      tenantId: req.tenantId,
      email,
      password,
      ipAddress: req.ip || '0.0.0.0',
    });
    const valid = identityService.verifyTotpFactor({
      tenantId: req.tenantId,
      userId: user.id,
      factorId,
      otpCode,
    });
    if (!valid) {
      throw new ForbiddenError('Invalid OTP');
    }
    res.json({ verified: true });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/login', requireTenant, (req, res, next) => {
  try {
    const {
      email,
      password,
      otp_code: otpCode,
      device_id: deviceId,
      device_name: deviceName = 'device',
      user_agent: bodyUserAgent = '',
      ip_address: ipAddress,
    } = req.body || {};

    if (!email || !password || !deviceId) {
      throw new ValidationError('email, password, and device_id are required');
    }

    const sourceIp = normalizeIp(ipAddress || req.ip || '0.0.0.0');
    const userAgent = req.header('user-agent') || bodyUserAgent || '';
    const user = identityService.authenticatePassword({
      tenantId: req.tenantId,
      email,
      password,
      ipAddress: sourceIp,
    });

    const hasMfa = identityService.hasVerifiedMfa({ tenantId: req.tenantId, userId: user.id });
    if (hasMfa) {
      const otpValid = identityService.verifyUserOtp({
        tenantId: req.tenantId,
        userId: user.id,
        otpCode,
      });
      if (!otpValid) {
        identityService.recordAuthAttempt({
          tenantId: req.tenantId,
          userId: user.id,
          email,
          success: false,
          ipAddress: sourceIp,
          reason: 'invalid_otp',
        });
        throw new ForbiddenError('OTP is required and must be valid');
      }
    }

    const device = deviceService.registerOrUpdate({
      tenantId: req.tenantId,
      userId: user.id,
      deviceId,
      deviceName,
      userAgent,
    });

    const anomalyScore = behaviorService.recentAnomalyScore({ tenantId: req.tenantId, userId: user.id });
    const authFailures = trustService.recentAuthFailures({ tenantId: req.tenantId, userId: user.id });
    const trust = trustService.calculate({
      user,
      device,
      session: null,
      mfaVerified: hasMfa,
      anomalyScore,
      authFailuresRecent: authFailures,
    });
    const risk = riskService.classify({
      trustScore: trust.trustScore,
      anomalyScore,
      authFailures,
      deviceCompromised: !!device.is_compromised,
    });

    const session = sessionService.create({
      tenantId: req.tenantId,
      userId: user.id,
      deviceId,
      authStrength: hasMfa ? 2 : 1,
      trustScore: trust.trustScore,
      riskLevel: risk.level,
      ipAddress: sourceIp,
      userAgent,
    });

    trustService.persistSnapshot({
      tenantId: req.tenantId,
      userId: user.id,
      sessionId: session.id,
      trustScore: trust.trustScore,
      riskLevel: risk.level,
      features: trust.features,
    });

    const roles = parseRoles(user.roles_json);
    const tokens = tokenService.issuePair({
      tenantId: req.tenantId,
      userId: user.id,
      sessionId: session.id,
      deviceId,
      roles,
      trustScore: trust.trustScore,
      riskLevel: risk.level,
      authStrength: hasMfa ? 2 : 1,
    });

    auditService.log({
      tenantId: req.tenantId,
      actorId: user.id,
      eventType: 'auth',
      actionName: 'login',
      targetId: user.id,
      decision: 'allow',
      metadata: { sessionId: session.id, risk: risk.level, trust: trust.trustScore },
    });

    res.json({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      token_type: 'bearer',
      expires_in: tokens.expiresIn,
      session_id: session.id,
      trust_score: trust.trustScore,
      risk_level: risk.level,
      user: {
        id: user.id,
        email: user.email,
        tenant_id: req.tenantId,
        roles,
      },
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/logout', requireTenant, requireAuth({ action: 'session:read', resource: 'session' }), (req, res, next) => {
  try {
    const session = sessionService.revoke({
      tenantId: req.tenantId,
      actorId: req.securityContext.userId,
      sessionId: req.securityContext.sessionId,
      reason: 'user_logout',
    });
    const revokedTokens = tokenService.revokeTokensForSession({
      tenantId: req.tenantId,
      sessionId: req.securityContext.sessionId,
      reason: 'user_logout',
    });
    auditService.log({
      tenantId: req.tenantId,
      actorId: req.securityContext.userId,
      eventType: 'auth',
      actionName: 'logout',
      targetId: req.securityContext.sessionId,
      decision: 'allow',
      metadata: {},
    });
    res.json({
      session_id: session.id,
      state: session.state,
      revoked_tokens: revokedTokens,
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/logout-all', requireTenant, requireAuth({ action: 'session:revoke_all', resource: 'session' }), (req, res, next) => {
  try {
    const sessions = sessionService.listByUser({
      tenantId: req.tenantId,
      userId: req.securityContext.userId,
    });

    let revokedTokens = 0;
    for (const session of sessions) {
      revokedTokens += tokenService.revokeTokensForSession({
        tenantId: req.tenantId,
        sessionId: session.id,
        reason: 'user_logout_all',
      });
    }

    const revokedSessions = sessionService.revokeAll({
      tenantId: req.tenantId,
      actorId: req.securityContext.userId,
      userId: req.securityContext.userId,
      reason: 'user_logout_all',
    });

    auditService.log({
      tenantId: req.tenantId,
      actorId: req.securityContext.userId,
      eventType: 'auth',
      actionName: 'logout_all',
      targetId: req.securityContext.userId,
      decision: 'allow',
      metadata: { revokedSessions, revokedTokens },
    });

    res.json({ revoked_sessions: revokedSessions, revoked_tokens: revokedTokens });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/step-up', requireTenant, requireAuth({ action: 'auth:step_up', resource: 'session' }), (req, res, next) => {
  try {
    const { password, otp_code: otpCode } = req.body || {};
    if (!password || !otpCode) {
      throw new ValidationError('password and otp_code are required');
    }

    const user = database.get(`SELECT * FROM users WHERE tenant_id = :tenantId AND id = :userId`, {
      tenantId: req.tenantId,
      userId: req.securityContext.userId,
    });

    identityService.authenticatePassword({
      tenantId: req.tenantId,
      email: user.email,
      password,
      ipAddress: normalizeIp(req.ip || '0.0.0.0'),
    });

    const otpValid = identityService.verifyUserOtp({
      tenantId: req.tenantId,
      userId: user.id,
      otpCode,
    });
    if (!otpValid) {
      throw new ForbiddenError('Invalid OTP');
    }

    database.run(
      `UPDATE sessions SET state = 'elevated', auth_strength = 3 WHERE id = :sessionId`,
      { sessionId: req.securityContext.sessionId }
    );

    auditService.log({
      tenantId: req.tenantId,
      actorId: user.id,
      eventType: 'auth',
      actionName: 'step_up',
      targetId: req.securityContext.sessionId,
      decision: 'allow',
      metadata: {},
    });

    res.json({ elevated: true, session_id: req.securityContext.sessionId });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  authRouter,
};

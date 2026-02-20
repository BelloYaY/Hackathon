const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');
const { requireSignedRequest } = require('../middleware/replayProtection');
const { tokenService } = require('../token/service');
const { signingKeyService } = require('../security/keyService');
const { auditService } = require('../audit/service');
const { ValidationError } = require('../core/errors');

const tokenRouter = express.Router();

tokenRouter.get('/jwks', (_req, res) => {
  res.json(signingKeyService.getJwks());
});

tokenRouter.post('/refresh', requireTenant, (req, res, next) => {
  try {
    const { refresh_token: refreshToken, device_id: deviceId } = req.body || {};
    if (!refreshToken || !deviceId) {
      throw new ValidationError('refresh_token and device_id are required');
    }
    const tokens = tokenService.refresh({ refreshToken, deviceId });
    res.json({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      token_type: 'bearer',
      expires_in: tokens.expiresIn,
    });
  } catch (err) {
    next(err);
  }
});

tokenRouter.post(
  '/revoke',
  requireTenant,
  requireAuth({ action: 'token:revoke', resource: 'token' }),
  (req, res, next) => {
    try {
      const { token, reason = 'requested' } = req.body || {};
      if (!token) {
        throw new ValidationError('token is required');
      }
      tokenService.revokeToken({
        actorId: req.securityContext.userId,
        tenantId: req.tenantId,
        tokenValue: token,
        reason,
      });
      res.json({ revoked: true });
    } catch (err) {
      next(err);
    }
  }
);

tokenRouter.post('/validate', requireTenant, requireSignedRequest, (req, res, next) => {
  try {
    const { token, device_id: deviceId } = req.body || {};
    if (!token) {
      throw new ValidationError('token is required');
    }
    const { claims } = tokenService.validateAccessToken({ token, deviceId: deviceId || undefined });

    if (claims.tid !== req.tenantId) {
      return res.json({
        active: false,
        reason: 'tenant_mismatch',
      });
    }

    return res.json({
      active: true,
      subject: claims.sub,
      tenant_id: claims.tid,
      session_id: claims.sid,
      claims,
    });
  } catch (err) {
    if (err.statusCode && err.statusCode < 500) {
      return res.json({ active: false, reason: err.message });
    }
    return next(err);
  }
});

tokenRouter.post(
  '/keys/rotate',
  requireTenant,
  requireAuth({ action: 'token:rotate_key', resource: 'token' }),
  requireSignedRequest,
  (req, res, next) => {
    try {
      const key = signingKeyService.rotateSigningKey();
      auditService.log({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        eventType: 'token',
        actionName: 'rotate_signing_key',
        targetId: key.kid,
        decision: 'allow',
        metadata: { algorithm: key.algorithm },
      });
      return res.json({
        rotated: true,
        kid: key.kid,
        algorithm: key.algorithm,
        activated_at: key.activatedAt,
      });
    } catch (err) {
      return next(err);
    }
  }
);

module.exports = {
  tokenRouter,
};

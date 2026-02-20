const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');
const { sessionService } = require('../session/service');
const { tokenService } = require('../token/service');

const sessionRouter = express.Router();

sessionRouter.get('/', requireTenant, requireAuth({ action: 'admin:session:list', resource: 'session' }), (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit || 100), 500);
    const offset = Math.max(Number(req.query.offset || 0), 0);
    const sessions = sessionService.listByTenant({
      tenantId: req.tenantId,
      limit,
      offset,
    });

    res.json(
      sessions.map((session) => ({
        id: session.id,
        user_id: session.user_id,
        user_email: session.user_email,
        device_id: session.device_id,
        state: session.state,
        auth_strength: session.auth_strength,
        trust_score: session.trust_score,
        risk_level: session.risk_level,
        ip_address: session.ip_address,
        user_agent: session.user_agent,
        last_activity_at: session.last_activity_at,
        expires_at: session.expires_at,
        created_at: session.created_at,
      }))
    );
  } catch (err) {
    next(err);
  }
});

sessionRouter.get('/me', requireTenant, requireAuth({ action: 'session:read', resource: 'session' }), (req, res, next) => {
  try {
    const session = sessionService.get({
      tenantId: req.tenantId,
      sessionId: req.securityContext.sessionId,
    });
    res.json({
      id: session.id,
      state: session.state,
      trust_score: session.trust_score,
      risk_level: session.risk_level,
      last_activity_at: session.last_activity_at,
      expires_at: session.expires_at,
    });
  } catch (err) {
    next(err);
  }
});

sessionRouter.post(
  '/:sessionId/lock',
  requireTenant,
  requireAuth({ action: 'admin:session:lock', resource: 'session' }),
  (req, res, next) => {
    try {
      const session = sessionService.lock({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        sessionId: req.params.sessionId,
        reason: req.body?.reason || 'manual_lock',
      });
      res.json({ session_id: session.id, state: session.state });
    } catch (err) {
      next(err);
    }
  }
);

sessionRouter.post(
  '/:sessionId/revoke',
  requireTenant,
  requireAuth({ action: 'admin:session:revoke', resource: 'session' }),
  (req, res, next) => {
    try {
      const reason = req.body?.reason || 'manual_revoke';
      const session = sessionService.revoke({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        sessionId: req.params.sessionId,
        reason,
      });
      const revokedTokens = tokenService.revokeTokensForSession({
        tenantId: req.tenantId,
        sessionId: session.id,
        reason: `session_revoked:${reason}`,
      });
      res.json({ session_id: session.id, state: session.state, revoked_tokens: revokedTokens });
    } catch (err) {
      next(err);
    }
  }
);

sessionRouter.post(
  '/:sessionId/unlock',
  requireTenant,
  requireAuth({ action: 'admin:session:unlock', resource: 'session' }),
  (req, res, next) => {
    try {
      const session = sessionService.unlock({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        sessionId: req.params.sessionId,
        reason: req.body?.reason || 'manual_unlock',
      });
      res.json({ session_id: session.id, state: session.state });
    } catch (err) {
      next(err);
    }
  }
);

sessionRouter.post('/revoke-all', requireTenant, requireAuth({ action: 'session:revoke_all', resource: 'session' }), (req, res, next) => {
  try {
    const affected = sessionService.revokeAll({
      tenantId: req.tenantId,
      actorId: req.securityContext.userId,
      userId: req.securityContext.userId,
      reason: req.body?.reason || 'user_logout_all',
    });
    res.json({ revoked_sessions: affected });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  sessionRouter,
};

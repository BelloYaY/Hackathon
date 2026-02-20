const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { settings } = require('../config/settings');
const { ForbiddenError, NotFoundError, UnauthorizedError } = require('../core/errors');
const { id, nowIso } = require('../utils/security');
const { normalizeIp } = require('../utils/context');

const SESSION_STATE = {
  INITIATED: 'initiated',
  ACTIVE: 'active',
  ELEVATED: 'elevated',
  LOCKED: 'locked',
  REVOKED: 'revoked',
  EXPIRED: 'expired',
  TERMINATED: 'terminated',
};

class SessionService {
  create({ tenantId, userId, deviceId, authStrength, trustScore, riskLevel, ipAddress, userAgent }) {
    const sessionId = id('sess');
    const expiresAt = new Date(Date.now() + settings.maxSessionSeconds * 1000).toISOString();
    const createdAt = nowIso();
    database.run(
      `INSERT INTO sessions (id, tenant_id, user_id, device_id, state, auth_strength, trust_score, risk_level, ip_address, user_agent, last_activity_at, expires_at, created_at)
       VALUES (:id, :tenantId, :userId, :deviceId, :state, :authStrength, :trustScore, :riskLevel, :ipAddress, :userAgent, :lastActivityAt, :expiresAt, :createdAt)`,
      {
        id: sessionId,
        tenantId,
        userId,
        deviceId,
        state: SESSION_STATE.ACTIVE,
        authStrength,
        trustScore,
        riskLevel,
        ipAddress,
        userAgent,
        lastActivityAt: createdAt,
        expiresAt,
        createdAt,
      }
    );

    auditService.log({
      tenantId,
      actorId: userId,
      eventType: 'session',
      actionName: 'create',
      targetId: sessionId,
      decision: 'allow',
      metadata: { trustScore, riskLevel },
    });

    return this.get({ tenantId, sessionId });
  }

  get({ tenantId, sessionId }) {
    const session = database.get(`SELECT * FROM sessions WHERE tenant_id = :tenantId AND id = :sessionId`, {
      tenantId,
      sessionId,
    });
    if (!session) {
      throw new NotFoundError('Session not found');
    }
    return session;
  }

  listByUser({ tenantId, userId }) {
    return database.all(`SELECT * FROM sessions WHERE tenant_id = :tenantId AND user_id = :userId`, {
      tenantId,
      userId,
    });
  }

  listByTenant({ tenantId, limit = 100, offset = 0 }) {
    return database.all(
      `SELECT
         s.*,
         u.email AS user_email
       FROM sessions s
       INNER JOIN users u
         ON u.id = s.user_id
        AND u.tenant_id = s.tenant_id
       WHERE s.tenant_id = :tenantId
       ORDER BY s.created_at DESC
       LIMIT :limit OFFSET :offset`,
      {
        tenantId,
        limit,
        offset,
      }
    );
  }

  validate({ session, requestDeviceId, requestIp }) {
    const baselineIp = normalizeIp(session.ip_address);
    const currentIp = normalizeIp(requestIp);
    if ([SESSION_STATE.REVOKED, SESSION_STATE.EXPIRED, SESSION_STATE.TERMINATED].includes(session.state)) {
      throw new UnauthorizedError('Session not active');
    }
    if (session.state === SESSION_STATE.LOCKED) {
      throw new ForbiddenError('Session is locked');
    }

    const now = Date.now();
    if (new Date(session.expires_at).getTime() <= now) {
      database.run(`UPDATE sessions SET state = :state WHERE id = :sessionId`, {
        state: SESSION_STATE.EXPIRED,
        sessionId: session.id,
      });
      throw new UnauthorizedError('Session expired');
    }

    const idleSeconds = (now - new Date(session.last_activity_at).getTime()) / 1000;
    if (idleSeconds > settings.idleSessionSeconds) {
      database.run(`UPDATE sessions SET state = :state WHERE id = :sessionId`, {
        state: SESSION_STATE.EXPIRED,
        sessionId: session.id,
      });
      throw new UnauthorizedError('Session idle timeout');
    }

    if (session.device_id !== requestDeviceId) {
      database.run(`UPDATE sessions SET state = :state WHERE id = :sessionId`, {
        state: SESSION_STATE.LOCKED,
        sessionId: session.id,
      });
      throw new ForbiddenError('Session device mismatch');
    }

    if (baselineIp !== currentIp) {
      database.run(
        `UPDATE sessions
         SET risk_level = 'elevated', trust_score = CASE WHEN trust_score > 20 THEN trust_score - 20 ELSE 0 END
         WHERE id = :sessionId`,
        { sessionId: session.id }
      );
    }

    database.run(`UPDATE sessions SET last_activity_at = :lastActivityAt WHERE id = :sessionId`, {
      lastActivityAt: nowIso(),
      sessionId: session.id,
    });

    return this.get({ tenantId: session.tenant_id, sessionId: session.id });
  }

  lock({ tenantId, actorId, sessionId, reason = 'manual_lock' }) {
    this.get({ tenantId, sessionId });
    database.run(`UPDATE sessions SET state = 'locked' WHERE id = :sessionId`, { sessionId });
    auditService.log({
      tenantId,
      actorId,
      eventType: 'session',
      actionName: 'lock',
      targetId: sessionId,
      decision: 'allow',
      metadata: { reason },
    });
    return this.get({ tenantId, sessionId });
  }

  revoke({ tenantId, actorId, sessionId, reason = 'manual_revoke' }) {
    this.get({ tenantId, sessionId });
    database.run(`UPDATE sessions SET state = 'revoked' WHERE id = :sessionId`, { sessionId });
    auditService.log({
      tenantId,
      actorId,
      eventType: 'session',
      actionName: 'revoke',
      targetId: sessionId,
      decision: 'allow',
      metadata: { reason },
    });
    return this.get({ tenantId, sessionId });
  }

  unlock({ tenantId, actorId, sessionId, reason = 'manual_unlock' }) {
    const session = this.get({ tenantId, sessionId });
    if (session.state !== SESSION_STATE.LOCKED) {
      throw new ForbiddenError('Session is not locked');
    }
    database.run(
      `UPDATE sessions SET state = :state, last_activity_at = :lastActivityAt WHERE id = :sessionId`,
      {
        state: SESSION_STATE.ACTIVE,
        lastActivityAt: nowIso(),
        sessionId,
      }
    );
    auditService.log({
      tenantId,
      actorId,
      eventType: 'session',
      actionName: 'unlock',
      targetId: sessionId,
      decision: 'allow',
      metadata: { reason },
    });
    return this.get({ tenantId, sessionId });
  }

  revokeAll({ tenantId, actorId, userId, reason }) {
    database.run(
      `UPDATE sessions SET state = 'revoked' WHERE tenant_id = :tenantId AND user_id = :userId AND state IN ('active', 'elevated', 'locked')`,
      { tenantId, userId }
    );
    const affected = database.get(
      `SELECT COUNT(*) AS count FROM sessions WHERE tenant_id = :tenantId AND user_id = :userId AND state = 'revoked'`,
      { tenantId, userId }
    ).count;
    auditService.log({
      tenantId,
      actorId,
      eventType: 'session',
      actionName: 'revoke_all',
      targetId: userId,
      decision: 'allow',
      metadata: { reason, affected },
    });
    return affected;
  }
}

const sessionService = new SessionService();

module.exports = {
  SESSION_STATE,
  sessionService,
};

const { database } = require('../database/db');
const { UnauthorizedError, ForbiddenError } = require('../core/errors');
const { tokenService } = require('../token/service');
const { sessionService } = require('../session/service');
const { deviceService } = require('../device/service');
const { behaviorService } = require('../behavior/service');
const { trustService } = require('../trust/service');
const { riskService } = require('../risk/service');
const { policyService } = require('../policy/service');
const { auditService } = require('../audit/service');
const { fingerprint, parseRoles } = require('../utils/context');

class EnforcementService {
  evaluateRequest({
    tenantId,
    accessToken,
    requestDeviceId,
    userAgent,
    ipAddress,
    action,
    resource,
    resourceOwnerId = null,
  }) {
    const { claims, tokenRow } = tokenService.validateAccessToken({
      token: accessToken,
      deviceId: requestDeviceId,
    });

    if (claims.tid !== tenantId || tokenRow.tenant_id !== tenantId) {
      throw new ForbiddenError('Cross-tenant token usage denied');
    }

    const session = sessionService.get({ tenantId, sessionId: claims.sid });
    const validatedSession = sessionService.validate({
      session,
      requestDeviceId,
      requestIp: ipAddress,
    });

    const device = deviceService.getDevice({ tenantId, deviceId: requestDeviceId });
    if (device.user_id !== claims.sub) {
      throw new ForbiddenError('Device owner mismatch');
    }
    deviceService.ensureUsable(device);

    const expectedFp = device.fingerprint_hash;
    const presentedFp = fingerprint({
      tenantId,
      userId: claims.sub,
      deviceId: requestDeviceId,
      userAgent,
    });

    const tokenTheftScore = behaviorService.detectTokenTheft({
      tokenDeviceId: claims.did,
      requestDeviceId,
    });
    const hijackScore = behaviorService.detectSessionHijacking({
      baselineIp: validatedSession.ip_address,
      currentIp: ipAddress,
    });
    const spoofScore = behaviorService.detectDeviceSpoofing({
      expectedFingerprint: expectedFp,
      presentedFingerprint: presentedFp,
    });

    const anomalyScore = Math.max(tokenTheftScore, hijackScore, spoofScore);
    if (anomalyScore > 0) {
      behaviorService.recordEvent({
        tenantId,
        userId: claims.sub,
        sessionId: validatedSession.id,
        eventType: 'anomaly',
        payload: {
          tokenTheftScore,
          hijackScore,
          spoofScore,
        },
        anomalyScore,
      });
    }

    if (tokenTheftScore >= 90) {
      sessionService.revoke({
        tenantId,
        actorId: claims.sub,
        sessionId: validatedSession.id,
        reason: 'token_theft_detected',
      });
      tokenService.revokeTokensForSession({
        tenantId,
        sessionId: validatedSession.id,
        reason: 'token_theft_detected',
      });
      riskService.recordEvent({
        tenantId,
        userId: claims.sub,
        sessionId: validatedSession.id,
        severity: 'critical',
        eventType: 'token_theft_detected',
        detail: { tokenDeviceId: claims.did, requestDeviceId },
      });
      throw new ForbiddenError('Token theft detected; access blocked');
    }

    if (spoofScore >= 90) {
      sessionService.lock({
        tenantId,
        actorId: claims.sub,
        sessionId: validatedSession.id,
        reason: 'device_spoofing_detected',
      });
      riskService.recordEvent({
        tenantId,
        userId: claims.sub,
        sessionId: validatedSession.id,
        severity: 'high',
        eventType: 'device_spoofing_detected',
        detail: {},
      });
      throw new ForbiddenError('Device spoofing detected; access blocked');
    }

    if (hijackScore >= 70) {
      sessionService.lock({
        tenantId,
        actorId: claims.sub,
        sessionId: validatedSession.id,
        reason: 'session_hijacking_detected',
      });
      riskService.recordEvent({
        tenantId,
        userId: claims.sub,
        sessionId: validatedSession.id,
        severity: 'high',
        eventType: 'session_hijacking_detected',
        detail: { baselineIp: validatedSession.ip_address, currentIp: ipAddress },
      });
      throw new ForbiddenError('Session hijacking suspected; access blocked');
    }

    const user = database.get(`SELECT * FROM users WHERE tenant_id = :tenantId AND id = :userId`, {
      tenantId,
      userId: claims.sub,
    });
    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    const mfaVerified = database.get(
      `SELECT id FROM mfa_factors WHERE tenant_id = :tenantId AND user_id = :userId AND is_verified = 1 LIMIT 1`,
      { tenantId, userId: user.id }
    );
    const authFailuresRecent = trustService.recentAuthFailures({ tenantId, userId: user.id });

    const trustData = trustService.calculate({
      user,
      device,
      session: validatedSession,
      mfaVerified: !!mfaVerified,
      anomalyScore,
      authFailuresRecent,
    });

    const riskData = riskService.classify({
      trustScore: trustData.trustScore,
      anomalyScore,
      authFailures: authFailuresRecent,
      deviceCompromised: !!device.is_compromised,
    });

    trustService.persistSnapshot({
      tenantId,
      userId: user.id,
      sessionId: validatedSession.id,
      trustScore: trustData.trustScore,
      riskLevel: riskData.level,
      features: trustData.features,
    });

    database.run(
      `UPDATE sessions SET trust_score = :trustScore, risk_level = :riskLevel WHERE id = :sessionId`,
      {
        trustScore: trustData.trustScore,
        riskLevel: riskData.level,
        sessionId: validatedSession.id,
      }
    );

    if (['high', 'critical'].includes(riskData.level)) {
      riskService.recordEvent({
        tenantId,
        userId: user.id,
        sessionId: validatedSession.id,
        severity: riskData.level,
        eventType: 'risk_escalation',
        detail: {
          reasons: riskData.reasons,
          anomalyScore,
          authFailuresRecent,
        },
      });
    }

    const decision = policyService.evaluate({
      tenantId,
      userId: user.id,
      roles: parseRoles(user.roles_json),
      action,
      resource,
      resourceOwnerId,
      trustScore: trustData.trustScore,
      riskLevel: riskData.level,
    });

    auditService.log({
      tenantId,
      actorId: user.id,
      eventType: 'enforcement',
      actionName: action,
      targetId: resource,
      decision: decision.decision,
      metadata: {
        reasons: decision.reasons,
        constraints: decision.constraints,
        trustScore: trustData.trustScore,
        riskLevel: riskData.level,
      },
    });

    if (decision.decision === 'deny') {
      throw new ForbiddenError(`Access denied: ${decision.reasons.join(',')}`);
    }
    if (decision.decision === 'step_up') {
      throw new ForbiddenError(`Step-up required: ${decision.reasons.join(',')}`);
    }

    return {
      tenantId,
      userId: user.id,
      sessionId: validatedSession.id,
      deviceId: requestDeviceId,
      authStrength: validatedSession.auth_strength,
      roles: parseRoles(user.roles_json),
      trustScore: trustData.trustScore,
      riskLevel: riskData.level,
      claims,
      policyDecision: decision,
    };
  }
}

const enforcementService = new EnforcementService();

module.exports = {
  enforcementService,
};

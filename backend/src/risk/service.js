const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { id, nowIso } = require('../utils/security');

class RiskService {
  classify({ trustScore, anomalyScore, authFailures, deviceCompromised }) {
    let points = Math.max(0, 100 - trustScore);
    const reasons = [];

    if (anomalyScore >= 70) {
      points += 40;
      reasons.push('behavior_anomaly_high');
    } else if (anomalyScore >= 40) {
      points += 20;
      reasons.push('behavior_anomaly_moderate');
    }

    if (authFailures >= 5) {
      points += 35;
      reasons.push('auth_failure_burst');
    } else if (authFailures >= 3) {
      points += 20;
      reasons.push('auth_failures_elevated');
    }

    if (deviceCompromised) {
      points += 50;
      reasons.push('device_compromised');
    }

    if (points >= 90) {
      return { level: 'critical', reasons: reasons.length ? reasons : ['baseline_critical'] };
    }
    if (points >= 70) {
      return { level: 'high', reasons: reasons.length ? reasons : ['baseline_high'] };
    }
    if (points >= 50) {
      return { level: 'elevated', reasons: reasons.length ? reasons : ['baseline_elevated'] };
    }
    if (points >= 25) {
      return { level: 'guarded', reasons: reasons.length ? reasons : ['baseline_guarded'] };
    }
    return { level: 'low', reasons: reasons.length ? reasons : ['baseline_low'] };
  }

  recordEvent({ tenantId, userId, sessionId = null, severity, eventType, detail = {} }) {
    const riskId = id('risk');
    database.run(
      `INSERT INTO risk_events (id, tenant_id, user_id, session_id, severity, event_type, detail_json, created_at)
       VALUES (:id, :tenantId, :userId, :sessionId, :severity, :eventType, :detailJson, :createdAt)`,
      {
        id: riskId,
        tenantId,
        userId,
        sessionId,
        severity,
        eventType,
        detailJson: JSON.stringify(detail),
        createdAt: nowIso(),
      }
    );

    auditService.log({
      tenantId,
      actorId: userId,
      eventType: 'risk',
      actionName: eventType,
      targetId: sessionId || userId,
      decision: 'record',
      metadata: { severity, ...detail },
    });

    return riskId;
  }
}

const riskService = new RiskService();

module.exports = {
  riskService,
};

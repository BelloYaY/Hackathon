const { database } = require('../database/db');
const { id, nowIso } = require('../utils/security');

class BehaviorService {
  recordEvent({ tenantId, userId, sessionId = null, eventType, payload = {}, anomalyScore = 0 }) {
    const eventId = id('beh');
    database.run(
      `INSERT INTO behavior_events (id, tenant_id, user_id, session_id, event_type, payload_json, anomaly_score, created_at)
       VALUES (:id, :tenantId, :userId, :sessionId, :eventType, :payloadJson, :anomalyScore, :createdAt)`,
      {
        id: eventId,
        tenantId,
        userId,
        sessionId,
        eventType,
        payloadJson: JSON.stringify(payload),
        anomalyScore,
        createdAt: nowIso(),
      }
    );
    return { eventId, anomalyScore };
  }

  recentAnomalyScore({ tenantId, userId }) {
    const rows = database.all(
      `SELECT anomaly_score FROM behavior_events
       WHERE tenant_id = :tenantId AND user_id = :userId
       AND datetime(created_at) >= datetime('now', '-30 minutes')`,
      {
        tenantId,
        userId,
      }
    );
    if (!rows.length) {
      return 0;
    }
    const avg = rows.reduce((sum, row) => sum + row.anomaly_score, 0) / rows.length;
    return Math.round(avg);
  }

  detectTokenTheft({ tokenDeviceId, requestDeviceId }) {
    return tokenDeviceId !== requestDeviceId ? 95 : 0;
  }

  detectSessionHijacking({ baselineIp, currentIp }) {
    return baselineIp !== currentIp ? 70 : 0;
  }

  detectDeviceSpoofing({ expectedFingerprint, presentedFingerprint }) {
    return expectedFingerprint !== presentedFingerprint ? 90 : 0;
  }

  detectReplay({ nonceSeen }) {
    return nonceSeen ? 85 : 0;
  }

  detectPrivilegeEscalation({ roles, action }) {
    return action.startsWith('admin:') && !roles.includes('admin') ? 88 : 0;
  }
}

const behaviorService = new BehaviorService();

module.exports = {
  behaviorService,
};

const { database } = require('../database/db');
const { id, nowIso } = require('../utils/security');

class TrustService {
  recentAuthFailures({ tenantId, userId }) {
    const rows = database.all(
      `SELECT id FROM auth_attempts
       WHERE tenant_id = :tenantId AND user_id = :userId AND success = 0
       AND datetime(created_at) >= datetime('now', '-15 minutes')`,
      { tenantId, userId }
    );
    return rows.length;
  }

  calculate({ user, device, session, mfaVerified, anomalyScore, authFailuresRecent }) {
    let score = 70;
    const features = {};

    if (mfaVerified) {
      score += 20;
      features.mfa_verified = 20;
    }

    if ((JSON.parse(user.roles_json || '[]')).includes('admin')) {
      score -= 5;
      features.privileged_identity_adjustment = -5;
    }

    if (device.is_approved && !device.is_compromised) {
      score += 15;
      features.device_approved = 15;
    }

    if (device.is_hardware_bound) {
      score += 10;
      features.hardware_bound = 10;
    }

    if (device.is_compromised) {
      score -= 40;
      features.device_compromised = -40;
    }

    if (session && session.state === 'elevated') {
      score += 5;
      features.elevated_session = 5;
    }

    if (anomalyScore > 0) {
      const penalty = Math.min(40, Math.floor(anomalyScore / 2));
      score -= penalty;
      features.anomaly_penalty = -penalty;
    }

    if (authFailuresRecent > 0) {
      const penalty = Math.min(30, authFailuresRecent * 5);
      score -= penalty;
      features.auth_failure_penalty = -penalty;
    }

    score = Math.max(0, Math.min(100, score));
    features.final_score = score;

    return {
      trustScore: score,
      features,
    };
  }

  persistSnapshot({ tenantId, userId, sessionId, trustScore, riskLevel, features }) {
    database.run(
      `INSERT INTO trust_snapshots (id, tenant_id, user_id, session_id, trust_score, risk_level, feature_json, created_at)
       VALUES (:id, :tenantId, :userId, :sessionId, :trustScore, :riskLevel, :featureJson, :createdAt)`,
      {
        id: id('trust'),
        tenantId,
        userId,
        sessionId,
        trustScore,
        riskLevel,
        featureJson: JSON.stringify(features),
        createdAt: nowIso(),
      }
    );
  }
}

const trustService = new TrustService();

module.exports = {
  trustService,
};

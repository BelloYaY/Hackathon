const express = require('express');

const { database } = require('../database/db');
const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');

const monitorRouter = express.Router();

monitorRouter.get('/security-overview', requireTenant, requireAuth({ action: 'audit:read', resource: 'monitor' }), (req, res) => {
  const tenantId = req.tenantId;
  const activeSessions = database.get(
    `SELECT COUNT(*) AS count FROM sessions WHERE tenant_id = :tenantId AND state IN ('active', 'elevated', 'locked')`,
    { tenantId }
  ).count;
  const highRiskEvents = database.get(
    `SELECT COUNT(*) AS count FROM risk_events WHERE tenant_id = :tenantId AND severity IN ('high', 'critical') AND datetime(created_at) >= datetime('now', '-24 hours')`,
    { tenantId }
  ).count;
  const anomalyEvents = database.get(
    `SELECT COUNT(*) AS count FROM behavior_events WHERE tenant_id = :tenantId AND anomaly_score >= 70 AND datetime(created_at) >= datetime('now', '-24 hours')`,
    { tenantId }
  ).count;
  const revokedTokens = database.get(
    `SELECT COUNT(*) AS count FROM tokens WHERE tenant_id = :tenantId AND revoked = 1`,
    { tenantId }
  ).count;

  return res.json({
    tenant_id: tenantId,
    active_sessions: activeSessions,
    high_risk_events_24h: highRiskEvents,
    high_anomaly_events_24h: anomalyEvents,
    revoked_tokens_total: revokedTokens,
  });
});

monitorRouter.get('/risk-events', requireTenant, requireAuth({ action: 'audit:read', resource: 'monitor' }), (req, res) => {
  const tenantId = req.tenantId;
  const limit = Math.min(Number(req.query.limit || 100), 500);
  const offset = Math.max(Number(req.query.offset || 0), 0);
  const severity = req.query.severity ? String(req.query.severity) : null;

  const where = ['tenant_id = :tenantId'];
  const params = { tenantId, limit, offset };
  if (severity) {
    where.push('severity = :severity');
    params.severity = severity;
  }

  const rows = database.all(
    `SELECT * FROM risk_events WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT :limit OFFSET :offset`,
    params
  );

  return res.json(
    rows.map((row) => ({
      id: row.id,
      user_id: row.user_id,
      session_id: row.session_id,
      severity: row.severity,
      event_type: row.event_type,
      detail: JSON.parse(row.detail_json || '{}'),
      created_at: row.created_at,
    }))
  );
});

monitorRouter.get('/behavior-events', requireTenant, requireAuth({ action: 'audit:read', resource: 'monitor' }), (req, res) => {
  const tenantId = req.tenantId;
  const limit = Math.min(Number(req.query.limit || 100), 500);
  const offset = Math.max(Number(req.query.offset || 0), 0);
  const eventType = req.query.event_type ? String(req.query.event_type) : null;

  const where = ['tenant_id = :tenantId'];
  const params = { tenantId, limit, offset };
  if (eventType) {
    where.push('event_type = :eventType');
    params.eventType = eventType;
  }

  const rows = database.all(
    `SELECT * FROM behavior_events WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT :limit OFFSET :offset`,
    params
  );

  return res.json(
    rows.map((row) => ({
      id: row.id,
      user_id: row.user_id,
      session_id: row.session_id,
      event_type: row.event_type,
      anomaly_score: row.anomaly_score,
      payload: JSON.parse(row.payload_json || '{}'),
      created_at: row.created_at,
    }))
  );
});

module.exports = {
  monitorRouter,
};

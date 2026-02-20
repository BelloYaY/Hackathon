const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');
const { auditService } = require('../audit/service');

const auditRouter = express.Router();

auditRouter.get('/integrity', requireTenant, requireAuth({ action: 'audit:read', resource: 'audit' }), (req, res, next) => {
  try {
    const result = auditService.verifyIntegrity(req.tenantId);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

auditRouter.get('/events', requireTenant, requireAuth({ action: 'audit:read', resource: 'audit' }), (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit || 100), 500);
    const offset = Math.max(Number(req.query.offset || 0), 0);
    const eventType = req.query.event_type ? String(req.query.event_type) : null;
    const actorId = req.query.actor_id ? String(req.query.actor_id) : null;
    const events = auditService.listEvents({
      tenantId: req.tenantId,
      limit,
      offset,
      eventType,
      actorId,
    });
    res.json(events);
  } catch (err) {
    next(err);
  }
});

module.exports = {
  auditRouter,
};

const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');
const { requireSignedRequest } = require('../middleware/replayProtection');
const { policyService } = require('../policy/service');
const { ValidationError } = require('../core/errors');

const policyRouter = express.Router();

policyRouter.post(
  '/',
  requireTenant,
  requireAuth({ action: 'policy:write', resource: 'policy' }),
  requireSignedRequest,
  (req, res, next) => {
    try {
      const { name, priority = 100, rules } = req.body || {};
      if (!name || !rules) {
        throw new ValidationError('name and rules are required');
      }
      const created = policyService.createPolicy({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        name,
        priority,
        rules,
      });
      res.status(201).json(created);
    } catch (err) {
      next(err);
    }
  }
);

policyRouter.post(
  '/evaluate',
  requireTenant,
  requireAuth({ action: 'policy:evaluate', resource: 'policy' }),
  (req, res, next) => {
    try {
      const { action, resource, resource_owner_id: resourceOwnerId = null } = req.body || {};
      if (!action || !resource) {
        throw new ValidationError('action and resource are required');
      }
      const decision = policyService.evaluate({
        tenantId: req.tenantId,
        userId: req.securityContext.userId,
        roles: req.securityContext.roles,
        action,
        resource,
        resourceOwnerId,
        trustScore: req.securityContext.trustScore,
        riskLevel: req.securityContext.riskLevel,
      });
      res.json(decision);
    } catch (err) {
      next(err);
    }
  }
);

module.exports = {
  policyRouter,
};

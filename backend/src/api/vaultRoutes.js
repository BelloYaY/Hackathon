const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');
const { requireSignedRequest } = require('../middleware/replayProtection');
const { vaultService } = require('../vault/service');
const { ValidationError, ForbiddenError } = require('../core/errors');

const vaultRouter = express.Router();

vaultRouter.post(
  '/secrets',
  requireTenant,
  requireAuth({ action: 'vault:write', resource: 'secret' }),
  requireSignedRequest,
  (req, res, next) => {
    try {
      const { name, value, secret_class: secretClass = 'standard' } = req.body || {};
      if (!name || !value) {
        throw new ValidationError('name and value are required');
      }
      if (secretClass === 'critical' && Number(req.securityContext.authStrength || 0) < 3) {
        throw new ForbiddenError('Step-up authentication required for critical secrets');
      }
      const secret = vaultService.createSecret({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        name,
        value,
        secretClass,
      });
      res.status(201).json(secret);
    } catch (err) {
      next(err);
    }
  }
);

vaultRouter.get(
  '/secrets/:secretId',
  requireTenant,
  requireAuth({ action: 'vault:read', resource: 'secret' }),
  (req, res, next) => {
    try {
      const secret = vaultService.readSecret({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        secretId: req.params.secretId,
      });
      res.json(secret);
    } catch (err) {
      next(err);
    }
  }
);

vaultRouter.post(
  '/secrets/:secretId/rotate',
  requireTenant,
  requireAuth({ action: 'vault:write', resource: 'secret' }),
  requireSignedRequest,
  (req, res, next) => {
    try {
      const { value } = req.body || {};
      if (!value) {
        throw new ValidationError('value is required');
      }
      const rotated = vaultService.rotateSecret({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        secretId: req.params.secretId,
        value,
      });
      res.json(rotated);
    } catch (err) {
      next(err);
    }
  }
);

module.exports = {
  vaultRouter,
};

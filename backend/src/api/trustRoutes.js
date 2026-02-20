const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');

const trustRouter = express.Router();

trustRouter.get('/me', requireTenant, requireAuth({ action: 'trust:read', resource: 'trust' }), (req, res) => {
  res.json({
    trust_score: req.securityContext.trustScore,
    risk_level: req.securityContext.riskLevel,
    reasons: req.securityContext.policyDecision.reasons,
  });
});

module.exports = {
  trustRouter,
};

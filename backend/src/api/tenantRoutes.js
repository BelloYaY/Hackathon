const express = require('express');

const { tenantService } = require('../tenant/service');
const { requireTenant } = require('../middleware/tenant');

const tenantRouter = express.Router();

tenantRouter.post('/bootstrap', (req, res, next) => {
  try {
    const bootstrapKey = req.header('x-bootstrap-key');
    const { tenant_id: tenantId, name, region = 'us', compliance_profile: complianceProfile = 'standard' } = req.body || {};
    const tenant = tenantService.bootstrap({
      bootstrapKey,
      tenantId,
      name,
      region,
      complianceProfile,
    });
    res.status(201).json(tenant);
  } catch (err) {
    next(err);
  }
});

tenantRouter.get('/me', requireTenant, (req, res, next) => {
  try {
    const tenant = tenantService.getTenant(req.tenantId);
    res.json({
      id: tenant.id,
      name: tenant.name,
      region: tenant.region,
      compliance_profile: tenant.compliance_profile,
      status: tenant.status,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  tenantRouter,
};

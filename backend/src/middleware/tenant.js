const { ValidationError } = require('../core/errors');
const { tenantService } = require('../tenant/service');

function requireTenant(req, _res, next) {
  const tenantId = (req.header('x-tenant-id') || '').trim();
  if (!tenantId) {
    return next(new ValidationError('Missing x-tenant-id header'));
  }

  try {
    // Ensure tenant context is valid before any downstream writes that rely on FK constraints.
    tenantService.getTenant(tenantId);
  } catch (err) {
    return next(err);
  }

  req.tenantId = tenantId;
  return next();
}

module.exports = {
  requireTenant,
};

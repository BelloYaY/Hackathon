const { ValidationError } = require('../core/errors');

function requireTenant(req, _res, next) {
  const tenantId = req.header('x-tenant-id');
  if (!tenantId) {
    return next(new ValidationError('Missing x-tenant-id header'));
  }
  req.tenantId = tenantId;
  return next();
}

module.exports = {
  requireTenant,
};

const { ValidationError, UnauthorizedError } = require('../core/errors');
const { normalizeIp, parseBearer } = require('../utils/context');
const { enforcementService } = require('../security/enforcement');

function requireAuth({ action, resource, getResourceOwnerId = null }) {
  return (req, _res, next) => {
    try {
      const token = parseBearer(req.header('authorization'));
      if (!token) {
        throw new UnauthorizedError('Missing bearer token');
      }
      const tenantId = req.tenantId;
      const deviceId = req.header('x-device-id');
      if (!deviceId) {
        throw new ValidationError('Missing x-device-id header');
      }

      const userAgent = req.header('user-agent') || '';
      const forwarded = req.header('x-forwarded-for');
      const ipAddress = normalizeIp(forwarded || req.ip || '0.0.0.0');
      const resourceOwnerId = getResourceOwnerId ? getResourceOwnerId(req) : null;

      const ctx = enforcementService.evaluateRequest({
        tenantId,
        accessToken: token,
        requestDeviceId: deviceId,
        userAgent,
        ipAddress,
        action,
        resource,
        resourceOwnerId,
      });

      req.securityContext = ctx;
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

module.exports = {
  requireAuth,
};

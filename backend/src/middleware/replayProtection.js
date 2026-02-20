const { settings } = require('../config/settings');
const { database } = require('../database/db');
const { ValidationError, ForbiddenError, ConflictError } = require('../core/errors');
const { id, nowIso, verifyRequestSignature } = require('../utils/security');

function requireSignedRequest(req, _res, next) {
  const tenantId = req.tenantId;
  const timestamp = req.header('x-request-timestamp');
  const nonce = req.header('x-request-nonce');
  const signature = req.header('x-request-signature');

  if (!timestamp || !nonce || !signature) {
    return next(new ValidationError('Missing request signature headers'));
  }

  const tsMs = Number(timestamp);
  if (!Number.isFinite(tsMs)) {
    return next(new ValidationError('Invalid x-request-timestamp'));
  }

  const skewMs = Math.abs(Date.now() - tsMs);
  if (skewMs > 5 * 60 * 1000) {
    return next(new ForbiddenError('Request timestamp outside allowed skew'));
  }

  const valid = verifyRequestSignature({
    secret: settings.requestSignatureSecret,
    timestamp,
    nonce,
    body: req.body || {},
    signature,
  });
  if (!valid) {
    return next(new ForbiddenError('Invalid request signature'));
  }

  const existing = database.get(
    `SELECT id FROM replay_nonces WHERE tenant_id = :tenantId AND nonce = :nonce`,
    { tenantId, nonce }
  );
  if (existing) {
    return next(new ConflictError('Replay attack detected: nonce reused'));
  }

  database.run(
    `INSERT INTO replay_nonces (id, tenant_id, nonce, signature, created_at)
     VALUES (:id, :tenantId, :nonce, :signature, :createdAt)`,
    {
      id: id('nonce'),
      tenantId,
      nonce,
      signature,
      createdAt: nowIso(),
    }
  );

  // Opportunistic cleanup of stale nonce records to bound table growth.
  if (Math.random() < 0.05) {
    database.run(
      `DELETE FROM replay_nonces WHERE datetime(created_at) < datetime('now', '-2 days')`
    );
  }

  return next();
}

module.exports = {
  requireSignedRequest,
};

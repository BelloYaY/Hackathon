const ALLOWED_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
const DEFAULT_ALLOWED_HEADERS =
  'Authorization,Content-Type,X-Tenant-Id,X-Device-Id,X-Bootstrap-Key,X-Request-Timestamp,X-Request-Nonce,X-Request-Signature,X-Forwarded-For';

function cors(req, res, next) {
  const requestOrigin = req.header('origin');
  const requestedHeaders = req.header('access-control-request-headers');

  // Keep API browser-friendly in development and demo setups.
  // Token auth is header-based (no cookies), so wildcard origin is acceptable here.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', ALLOWED_METHODS);
  res.setHeader('Access-Control-Allow-Headers', requestedHeaders || DEFAULT_ALLOWED_HEADERS);
  res.setHeader('Access-Control-Expose-Headers', 'X-Request-Id');

  if (requestOrigin) {
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  return next();
}

module.exports = {
  cors,
};

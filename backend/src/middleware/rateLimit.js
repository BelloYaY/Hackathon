const buckets = new Map();

function rateLimit({ windowMs = 60_000, max = 100 } = {}) {
  return (req, _res, next) => {
    const tenantId = req.header('x-tenant-id') || 'none';
    const forwarded = req.header('x-forwarded-for');
    const rawIp = forwarded ? forwarded.split(',')[0].trim() : req.ip;
    const ip = rawIp && rawIp.startsWith('::ffff:') ? rawIp.slice(7) : (rawIp || '0.0.0.0');
    const key = `${ip}:${req.path}:${tenantId}`;
    const now = Date.now();
    const bucket = buckets.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + windowMs;
    }

    bucket.count += 1;
    buckets.set(key, bucket);

    let effectiveMax = max;
    if (req.path.endsWith('/auth/login')) {
      effectiveMax = Math.min(max, 20);
    } else if (req.path.endsWith('/auth/mfa/verify')) {
      effectiveMax = Math.min(max, 30);
    } else if (req.path.endsWith('/token/validate')) {
      effectiveMax = Math.min(max, 300);
    }

    if (bucket.count > effectiveMax) {
      const err = new Error('Rate limit exceeded');
      err.statusCode = 429;
      return next(err);
    }

    return next();
  };
}

module.exports = {
  rateLimit,
};

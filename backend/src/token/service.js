const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { settings } = require('../config/settings');
const { ForbiddenError, UnauthorizedError } = require('../core/errors');
const jwt = require('jsonwebtoken');
const { signingKeyService } = require('../security/keyService');
const { id, nowIso, randomToken, sha256 } = require('../utils/security');

class TokenService {
  issuePair({ tenantId, userId, sessionId, deviceId, roles, trustScore, riskLevel, authStrength }) {
    const accessJti = id('atjti');
    const refreshJti = id('rtjti');
    const activeKey = signingKeyService.getActiveSigningKey();

    const payload = {
      sub: userId,
      tid: tenantId,
      sid: sessionId,
      did: deviceId,
      roles,
      trust: trustScore,
      risk: riskLevel,
      auth_strength: authStrength,
      jti: accessJti,
      scope: ['identity:read', 'device:read', 'session:read', 'vault:read'],
    };
    if (roles.includes('admin')) {
      payload.scope.push('policy:write', 'vault:write', 'tenant:admin', 'audit:read');
    }

    const accessToken = jwt.sign(payload, activeKey.privateKeyPem, {
      algorithm: activeKey.algorithm,
      keyid: activeKey.kid,
      issuer: settings.jwtIssuer,
      audience: settings.jwtAudience,
      expiresIn: settings.accessTtlSeconds,
      notBefore: 0,
    });
    const refreshToken = randomToken(48);

    const now = Date.now();
    const accessExpiresAt = new Date(now + settings.accessTtlSeconds * 1000).toISOString();
    const refreshExpiresAt = new Date(now + settings.refreshTtlSeconds * 1000).toISOString();

    database.run(
      `INSERT INTO tokens (id, tenant_id, user_id, session_id, device_id, jti, token_type, token_hash, parent_jti, revoked, expires_at, created_at)
       VALUES (:id, :tenantId, :userId, :sessionId, :deviceId, :jti, 'access', :tokenHash, NULL, 0, :expiresAt, :createdAt)`,
      {
        id: id('tok'),
        tenantId,
        userId,
        sessionId,
        deviceId,
        jti: accessJti,
        tokenHash: sha256(accessToken),
        expiresAt: accessExpiresAt,
        createdAt: nowIso(),
      }
    );

    database.run(
      `INSERT INTO tokens (id, tenant_id, user_id, session_id, device_id, jti, token_type, token_hash, parent_jti, revoked, expires_at, created_at)
       VALUES (:id, :tenantId, :userId, :sessionId, :deviceId, :jti, 'refresh', :tokenHash, :parentJti, 0, :expiresAt, :createdAt)`,
      {
        id: id('tok'),
        tenantId,
        userId,
        sessionId,
        deviceId,
        jti: refreshJti,
        tokenHash: sha256(refreshToken),
        parentJti: accessJti,
        expiresAt: refreshExpiresAt,
        createdAt: nowIso(),
      }
    );

    auditService.log({
      tenantId,
      actorId: userId,
      eventType: 'token',
      actionName: 'issue',
      targetId: sessionId,
      decision: 'allow',
      metadata: { accessJti, refreshJti, deviceId, signingKid: activeKey.kid },
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: settings.accessTtlSeconds,
      accessJti,
      refreshJti,
    };
  }

  decodeAccessToken(token) {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded !== 'object' || !decoded.header || !decoded.payload) {
      throw new UnauthorizedError('Invalid token format');
    }

    const kid = decoded.header.kid;
    if (!kid) {
      throw new UnauthorizedError('Token missing key identifier');
    }
    const key = signingKeyService.getVerificationKeyByKid(kid);
    if (!key) {
      throw new UnauthorizedError('Unknown signing key');
    }
    return jwt.verify(token, key.publicKeyPem, {
      algorithms: [key.algorithm],
      issuer: settings.jwtIssuer,
      audience: settings.jwtAudience,
    });
  }

  validateAccessToken({ token, deviceId }) {
    let claims;
    try {
      claims = this.decodeAccessToken(token);
    } catch {
      throw new UnauthorizedError('Invalid token');
    }

    const tokenRow = database.get(`SELECT * FROM tokens WHERE jti = :jti AND token_type = 'access'`, {
      jti: claims.jti,
    });

    if (!tokenRow) {
      throw new UnauthorizedError('Unknown token');
    }
    if (tokenRow.revoked) {
      throw new UnauthorizedError('Token revoked');
    }
    if (new Date(tokenRow.expires_at).getTime() <= Date.now()) {
      throw new UnauthorizedError('Token expired');
    }
    if (sha256(token) !== tokenRow.token_hash) {
      throw new UnauthorizedError('Token hash mismatch');
    }

    const revocation = database.get(
      `SELECT id FROM revocations WHERE tenant_id = :tenantId AND revocation_type = 'token' AND target_id = :targetId LIMIT 1`,
      {
        tenantId: tokenRow.tenant_id,
        targetId: tokenRow.jti,
      }
    );
    if (revocation) {
      throw new UnauthorizedError('Token revoked');
    }

    if (deviceId && claims.did !== deviceId) {
      throw new ForbiddenError('Token-device binding mismatch');
    }

    return {
      claims,
      tokenRow,
    };
  }

  refresh({ refreshToken, deviceId }) {
    const row = database.get(`SELECT * FROM tokens WHERE token_type = 'refresh' AND token_hash = :tokenHash`, {
      tokenHash: sha256(refreshToken),
    });

    if (!row) {
      throw new UnauthorizedError('Invalid refresh token');
    }

    if (row.revoked) {
      this.revokeTokenChain({ tenantId: row.tenant_id, rootJti: row.jti, reason: 'refresh_reuse_detected' });
      throw new UnauthorizedError('Refresh token reuse detected');
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      database.run(`UPDATE tokens SET revoked = 1 WHERE id = :id`, { id: row.id });
      throw new UnauthorizedError('Refresh token expired');
    }

    if (row.device_id !== deviceId) {
      this.revokeTokenChain({ tenantId: row.tenant_id, rootJti: row.jti, reason: 'device_binding_mismatch' });
      throw new ForbiddenError('Refresh token device mismatch');
    }

    database.run(`UPDATE tokens SET revoked = 1 WHERE id = :id`, { id: row.id });

    const userRow = database.get(`SELECT roles_json FROM users WHERE id = :userId AND tenant_id = :tenantId`, {
      userId: row.user_id,
      tenantId: row.tenant_id,
    });
    const roles = userRow ? JSON.parse(userRow.roles_json) : ['user'];

    return this.issuePair({
      tenantId: row.tenant_id,
      userId: row.user_id,
      sessionId: row.session_id,
      deviceId: row.device_id,
      roles,
      trustScore: 50,
      riskLevel: 'guarded',
      authStrength: 2,
    });
  }

  revokeToken({ actorId, tenantId, tokenValue, reason }) {
    let tokenRow = null;
    let jti = null;

    if ((tokenValue.match(/\./g) || []).length === 2) {
      const claims = this.decodeAccessToken(tokenValue);
      jti = claims.jti;
      tokenRow = database.get(`SELECT * FROM tokens WHERE tenant_id = :tenantId AND jti = :jti`, {
        tenantId,
        jti,
      });
    } else {
      tokenRow = database.get(`SELECT * FROM tokens WHERE tenant_id = :tenantId AND token_hash = :tokenHash`, {
        tenantId,
        tokenHash: sha256(tokenValue),
      });
      jti = tokenRow ? tokenRow.jti : null;
    }

    if (!tokenRow || !jti) {
      throw new UnauthorizedError('Token not found');
    }

    database.run(`UPDATE tokens SET revoked = 1 WHERE id = :id`, { id: tokenRow.id });
    database.run(
      `INSERT INTO revocations (id, tenant_id, revocation_type, target_id, reason, created_at)
       VALUES (:id, :tenantId, 'token', :targetId, :reason, :createdAt)`,
      {
        id: id('rev'),
        tenantId,
        targetId: jti,
        reason,
        createdAt: nowIso(),
      }
    );

    auditService.log({
      tenantId,
      actorId,
      eventType: 'token',
      actionName: 'revoke',
      targetId: jti,
      decision: 'allow',
      metadata: { reason },
    });
  }

  revokeTokensForSession({ tenantId, sessionId, reason }) {
    const rows = database.all(`SELECT id, jti FROM tokens WHERE tenant_id = :tenantId AND session_id = :sessionId AND revoked = 0`, {
      tenantId,
      sessionId,
    });
    for (const row of rows) {
      database.run(`UPDATE tokens SET revoked = 1 WHERE id = :id`, { id: row.id });
      database.run(
        `INSERT INTO revocations (id, tenant_id, revocation_type, target_id, reason, created_at)
         VALUES (:id, :tenantId, 'token', :targetId, :reason, :createdAt)`,
        {
          id: id('rev'),
          tenantId,
          targetId: row.jti,
          reason,
          createdAt: nowIso(),
        }
      );
    }
    return rows.length;
  }

  revokeTokenChain({ tenantId, rootJti, reason }) {
    const rows = database.all(`SELECT id, jti, parent_jti FROM tokens WHERE tenant_id = :tenantId`, { tenantId });
    for (const row of rows) {
      if (row.jti === rootJti || row.parent_jti === rootJti) {
        database.run(`UPDATE tokens SET revoked = 1 WHERE id = :id`, { id: row.id });
        database.run(
          `INSERT INTO revocations (id, tenant_id, revocation_type, target_id, reason, created_at)
           VALUES (:id, :tenantId, 'token', :targetId, :reason, :createdAt)`,
          {
            id: id('rev'),
            tenantId,
            targetId: row.jti,
            reason,
            createdAt: nowIso(),
          }
        );
      }
    }
  }
}

const tokenService = new TokenService();

module.exports = {
  tokenService,
};

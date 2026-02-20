const crypto = require('crypto');

const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { ForbiddenError, NotFoundError } = require('../core/errors');
const { id, nowIso, randomToken } = require('../utils/security');
const { fingerprint, parseRoles } = require('../utils/context');

const TRUST = {
  UNKNOWN: 'unknown',
  OBSERVED: 'observed',
  REGISTERED: 'registered',
  TRUSTED: 'trusted',
  RESTRICTED: 'restricted',
  REVOKED: 'revoked',
};

class DeviceService {
  registerOrUpdate({ tenantId, userId, deviceId, deviceName, userAgent }) {
    const fp = fingerprint({ tenantId, userId, deviceId, userAgent });
    const existing = database.get(
      `SELECT * FROM devices WHERE tenant_id = :tenantId AND id = :deviceId AND user_id = :userId`,
      { tenantId, deviceId, userId }
    );
    const existingTenantDevice = database.get(
      `SELECT * FROM devices WHERE tenant_id = :tenantId AND id = :deviceId`,
      { tenantId, deviceId }
    );
    const existingGlobalDevice = database.get(
      `SELECT * FROM devices WHERE id = :deviceId`,
      { deviceId }
    );

    if (!existing) {
      if (existingTenantDevice && existingTenantDevice.user_id !== userId) {
        auditService.log({
          tenantId,
          actorId: userId,
          eventType: 'device',
          actionName: 'register_conflict',
          targetId: deviceId,
          decision: 'deny',
          metadata: {
            reason: 'device_already_bound_to_another_user',
            owner: existingTenantDevice.user_id,
          },
        });
        throw new ForbiddenError('Device already bound to another user in this tenant');
      }
      if (existingGlobalDevice && existingGlobalDevice.tenant_id !== tenantId) {
        auditService.log({
          tenantId,
          actorId: userId,
          eventType: 'device',
          actionName: 'register_conflict',
          targetId: deviceId,
          decision: 'deny',
          metadata: {
            reason: 'device_id_collision_across_tenants',
            owner_tenant: existingGlobalDevice.tenant_id,
          },
        });
        throw new ForbiddenError('Device ID collision detected; use a unique device_id');
      }

      database.run(
        `INSERT INTO devices
         (id, tenant_id, user_id, device_name, fingerprint_hash, fingerprint_confidence, trust_tier, is_approved, is_compromised, is_hardware_bound, attestation_level, last_seen_at, created_at)
         VALUES (:id, :tenantId, :userId, :deviceName, :fingerprintHash, 75, :trustTier, 0, 0, 0, 'none', :lastSeenAt, :createdAt)`,
        {
          id: deviceId,
          tenantId,
          userId,
          deviceName,
          fingerprintHash: fp,
          trustTier: TRUST.OBSERVED,
          lastSeenAt: nowIso(),
          createdAt: nowIso(),
        }
      );
      auditService.log({
        tenantId,
        actorId: userId,
        eventType: 'device',
        actionName: 'register',
        targetId: deviceId,
        decision: 'allow',
        metadata: { fingerprintConfidence: 75 },
      });
    } else {
      if (existing.fingerprint_hash !== fp) {
        database.run(
          `UPDATE devices SET trust_tier = :trustTier, is_compromised = 1, last_seen_at = :ts WHERE id = :deviceId`,
          { trustTier: TRUST.RESTRICTED, ts: nowIso(), deviceId }
        );
        auditService.log({
          tenantId,
          actorId: userId,
          eventType: 'device',
          actionName: 'fingerprint_mismatch',
          targetId: deviceId,
          decision: 'deny',
          metadata: {},
        });
      } else {
        database.run(
          `UPDATE devices SET last_seen_at = :ts WHERE id = :deviceId`,
          { ts: nowIso(), deviceId }
        );
      }
    }

    return this.getDevice({ tenantId, deviceId });
  }

  getDevice({ tenantId, deviceId }) {
    const device = database.get(`SELECT * FROM devices WHERE tenant_id = :tenantId AND id = :deviceId`, {
      tenantId,
      deviceId,
    });
    if (!device) {
      throw new NotFoundError('Device not found');
    }
    return device;
  }

  listUserDevices({ tenantId, userId }) {
    return database.all(`SELECT * FROM devices WHERE tenant_id = :tenantId AND user_id = :userId`, {
      tenantId,
      userId,
    });
  }

  listTenantDevices({ tenantId, limit = 100, offset = 0 }) {
    return database.all(
      `SELECT
         d.*,
         u.email AS user_email
       FROM devices d
       INNER JOIN users u
         ON u.id = d.user_id
        AND u.tenant_id = d.tenant_id
       WHERE d.tenant_id = :tenantId
       ORDER BY d.last_seen_at DESC, d.created_at DESC
       LIMIT :limit OFFSET :offset`,
      {
        tenantId,
        limit,
        offset,
      }
    );
  }

  approveDevice({ tenantId, actorId, deviceId }) {
    const device = this.getDevice({ tenantId, deviceId });
    database.run(
      `UPDATE devices SET is_approved = 1, trust_tier = :trustTier WHERE id = :deviceId`,
      {
        trustTier: device.is_compromised ? TRUST.RESTRICTED : TRUST.TRUSTED,
        deviceId,
      }
    );
    auditService.log({
      tenantId,
      actorId,
      eventType: 'device',
      actionName: 'approve',
      targetId: deviceId,
      decision: 'allow',
      metadata: {},
    });
    return this.getDevice({ tenantId, deviceId });
  }

  revokeDevice({ tenantId, actorId, deviceId, reason = 'revoked' }) {
    this.getDevice({ tenantId, deviceId });
    database.run(
      `UPDATE devices SET trust_tier = :trustTier, is_approved = 0, is_compromised = 1 WHERE id = :deviceId`,
      {
        trustTier: TRUST.REVOKED,
        deviceId,
      }
    );
    database.run(
      `UPDATE sessions SET state = 'revoked' WHERE tenant_id = :tenantId AND device_id = :deviceId AND state IN ('active', 'elevated', 'locked')`,
      { tenantId, deviceId }
    );
    database.run(
      `UPDATE tokens SET revoked = 1 WHERE tenant_id = :tenantId AND device_id = :deviceId`,
      { tenantId, deviceId }
    );

    auditService.log({
      tenantId,
      actorId,
      eventType: 'device',
      actionName: 'revoke',
      targetId: deviceId,
      decision: 'allow',
      metadata: { reason },
    });

    return this.getDevice({ tenantId, deviceId });
  }

  ensureUsable(device) {
    if (device.trust_tier === TRUST.REVOKED) {
      throw new ForbiddenError('Device is revoked');
    }
    if (device.is_compromised) {
      throw new ForbiddenError('Device is compromised');
    }
  }

  registerHardwareKey({ tenantId, actorId, deviceId, publicKeyPem, attestationLevel }) {
    const device = this.getDevice({ tenantId, deviceId });
    const actor = database.get(`SELECT roles_json FROM users WHERE tenant_id = :tenantId AND id = :actorId`, {
      tenantId,
      actorId,
    });
    const roles = actor ? parseRoles(actor.roles_json) : [];
    if (actorId !== device.user_id && !roles.includes('admin')) {
      throw new ForbiddenError('Cannot bind hardware key for another user');
    }

    try {
      crypto.createPublicKey(publicKeyPem);
    } catch {
      throw new ForbiddenError('Invalid public key');
    }

    database.run(
      `UPDATE devices SET public_key_pem = :publicKeyPem, is_hardware_bound = 1, attestation_level = :attestationLevel WHERE id = :deviceId`,
      { publicKeyPem, attestationLevel, deviceId }
    );

    auditService.log({
      tenantId,
      actorId,
      eventType: 'device',
      actionName: 'hardware_bind',
      targetId: deviceId,
      decision: 'allow',
      metadata: { attestationLevel },
    });

    return this.getDevice({ tenantId, deviceId });
  }

  createChallenge({ tenantId, actorId, deviceId }) {
    const device = this.getDevice({ tenantId, deviceId });
    if (!device.public_key_pem) {
      throw new ForbiddenError('Hardware key not configured');
    }
    const actor = database.get(`SELECT roles_json FROM users WHERE tenant_id = :tenantId AND id = :actorId`, {
      tenantId,
      actorId,
    });
    const roles = actor ? parseRoles(actor.roles_json) : [];
    if (actorId !== device.user_id && !roles.includes('admin')) {
      throw new ForbiddenError('Cannot challenge another user device');
    }

    const challengeId = id('chall');
    const nonce = randomToken(24);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    database.run(
      `INSERT INTO device_challenges (id, tenant_id, device_id, nonce, expires_at, used, created_at)
       VALUES (:id, :tenantId, :deviceId, :nonce, :expiresAt, 0, :createdAt)`,
      {
        id: challengeId,
        tenantId,
        deviceId,
        nonce,
        expiresAt,
        createdAt: nowIso(),
      }
    );

    return {
      challengeId,
      nonce,
      expiresAt,
    };
  }

  attestChallenge({ tenantId, actorId, deviceId, challengeId, signatureB64 }) {
    const challenge = database.get(
      `SELECT * FROM device_challenges WHERE tenant_id = :tenantId AND id = :challengeId AND device_id = :deviceId`,
      { tenantId, challengeId, deviceId }
    );
    if (!challenge) {
      throw new NotFoundError('Challenge not found');
    }
    if (challenge.used) {
      throw new ForbiddenError('Challenge already used');
    }
    if (new Date(challenge.expires_at).getTime() < Date.now()) {
      throw new ForbiddenError('Challenge expired');
    }

    const device = this.getDevice({ tenantId, deviceId });
    const actor = database.get(`SELECT roles_json FROM users WHERE tenant_id = :tenantId AND id = :actorId`, {
      tenantId,
      actorId,
    });
    const roles = actor ? parseRoles(actor.roles_json) : [];
    if (actorId !== device.user_id && !roles.includes('admin')) {
      throw new ForbiddenError('Cannot attest another user device');
    }
    if (!device.public_key_pem) {
      throw new ForbiddenError('No hardware key configured');
    }

    const publicKey = crypto.createPublicKey(device.public_key_pem);
    const signature = Buffer.from(signatureB64, 'base64');

    const valid = crypto.verify(
      null,
      Buffer.from(challenge.nonce, 'utf8'),
      publicKey,
      signature
    );

    if (!valid) {
      throw new ForbiddenError('Invalid hardware signature');
    }

    database.run(`UPDATE device_challenges SET used = 1 WHERE id = :challengeId`, { challengeId });
    database.run(
      `UPDATE devices SET is_hardware_bound = 1, trust_tier = CASE WHEN is_approved = 1 THEN :trusted ELSE trust_tier END WHERE id = :deviceId`,
      {
        trusted: TRUST.TRUSTED,
        deviceId,
      }
    );

    auditService.log({
      tenantId,
      actorId,
      eventType: 'device',
      actionName: 'hardware_attest',
      targetId: deviceId,
      decision: 'allow',
      metadata: { challengeId },
    });

    return this.getDevice({ tenantId, deviceId });
  }
}

const deviceService = new DeviceService();

module.exports = {
  TRUST,
  deviceService,
};

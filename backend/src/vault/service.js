const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { ForbiddenError, NotFoundError } = require('../core/errors');
const { tenantService } = require('../tenant/service');
const { id, nowIso, encryptSecretValue, decryptSecretValue } = require('../utils/security');

class VaultService {
  createSecret({ tenantId, actorId, name, value, secretClass = 'standard' }) {
    const existing = database.get(
      `SELECT id FROM secrets WHERE tenant_id = :tenantId AND name = :name`,
      { tenantId, name }
    );
    if (existing) {
      throw new ForbiddenError('Secret with this name already exists');
    }

    const tenantDek = tenantService.getTenantDek(tenantId);
    const encrypted = encryptSecretValue(tenantDek, value);

    const secretId = id('sec');
    const createdAt = nowIso();

    database.run(
      `INSERT INTO secrets (id, tenant_id, name, secret_class, created_by, current_version, created_at)
       VALUES (:id, :tenantId, :name, :secretClass, :createdBy, 1, :createdAt)`,
      {
        id: secretId,
        tenantId,
        name,
        secretClass,
        createdBy: actorId,
        createdAt,
      }
    );

    database.run(
      `INSERT INTO secret_versions (id, tenant_id, secret_id, version, nonce_b64, ciphertext_b64, expires_at, created_at)
       VALUES (:id, :tenantId, :secretId, 1, :nonceB64, :ciphertextB64, NULL, :createdAt)`,
      {
        id: id('secver'),
        tenantId,
        secretId,
        nonceB64: encrypted.nonceB64,
        ciphertextB64: encrypted.ciphertextB64,
        createdAt,
      }
    );

    auditService.log({
      tenantId,
      actorId,
      eventType: 'vault',
      actionName: 'create_secret',
      targetId: secretId,
      decision: 'allow',
      metadata: { name, secretClass },
    });

    return { id: secretId, name, version: 1 };
  }

  readSecret({ tenantId, actorId, secretId }) {
    const secret = database.get(
      `SELECT * FROM secrets WHERE tenant_id = :tenantId AND id = :secretId`,
      { tenantId, secretId }
    );
    if (!secret) {
      throw new NotFoundError('Secret not found');
    }

    const version = database.get(
      `SELECT * FROM secret_versions WHERE tenant_id = :tenantId AND secret_id = :secretId AND version = :version`,
      {
        tenantId,
        secretId,
        version: secret.current_version,
      }
    );
    if (!version) {
      throw new NotFoundError('Secret version not found');
    }

    const tenantDek = tenantService.getTenantDek(tenantId);
    const value = decryptSecretValue(tenantDek, version.nonce_b64, version.ciphertext_b64);

    auditService.log({
      tenantId,
      actorId,
      eventType: 'vault',
      actionName: 'read_secret',
      targetId: secretId,
      decision: 'allow',
      metadata: { version: secret.current_version },
    });

    return {
      id: secret.id,
      name: secret.name,
      version: secret.current_version,
      value,
    };
  }

  rotateSecret({ tenantId, actorId, secretId, value }) {
    const secret = database.get(
      `SELECT * FROM secrets WHERE tenant_id = :tenantId AND id = :secretId`,
      { tenantId, secretId }
    );
    if (!secret) {
      throw new NotFoundError('Secret not found');
    }

    const nextVersion = Number(secret.current_version) + 1;
    const tenantDek = tenantService.getTenantDek(tenantId);
    const encrypted = encryptSecretValue(tenantDek, value);

    database.run(
      `INSERT INTO secret_versions (id, tenant_id, secret_id, version, nonce_b64, ciphertext_b64, expires_at, created_at)
       VALUES (:id, :tenantId, :secretId, :version, :nonceB64, :ciphertextB64, NULL, :createdAt)`,
      {
        id: id('secver'),
        tenantId,
        secretId,
        version: nextVersion,
        nonceB64: encrypted.nonceB64,
        ciphertextB64: encrypted.ciphertextB64,
        createdAt: nowIso(),
      }
    );

    database.run(`UPDATE secrets SET current_version = :version WHERE id = :secretId`, {
      version: nextVersion,
      secretId,
    });

    auditService.log({
      tenantId,
      actorId,
      eventType: 'vault',
      actionName: 'rotate_secret',
      targetId: secretId,
      decision: 'allow',
      metadata: { version: nextVersion },
    });

    return { id: secretId, name: secret.name, version: nextVersion };
  }
}

const vaultService = new VaultService();

module.exports = {
  vaultService,
};

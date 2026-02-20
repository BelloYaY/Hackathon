const crypto = require('crypto');

const { settings } = require('../config/settings');
const { database } = require('../database/db');
const { id, nowIso, encryptWithMaster, decryptWithMaster } = require('../utils/security');

class SigningKeyService {
  ensureInitialized() {
    const existingActive = database.get(`SELECT id FROM signing_keys WHERE status = 'active' LIMIT 1`);
    if (existingActive) {
      return;
    }
    this._createActiveKey();
  }

  _createActiveKey() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const kid = id('kid');
    const createdAt = nowIso();
    const encryptedPrivate = encryptWithMaster(settings.masterEncryptionKey, privateKey);

    database.run(
      `INSERT INTO signing_keys (id, kid, algorithm, status, public_key_pem, private_key_pem, created_at, activated_at, rotated_at)
       VALUES (:id, :kid, 'RS256', 'active', :publicKeyPem, :privateKeyPem, :createdAt, :activatedAt, NULL)`,
      {
        id: id('skey'),
        kid,
        publicKeyPem: publicKey,
        privateKeyPem: encryptedPrivate,
        createdAt,
        activatedAt: createdAt,
      }
    );
  }

  getActiveSigningKey() {
    this.ensureInitialized();
    const row = database.get(`SELECT * FROM signing_keys WHERE status = 'active' ORDER BY created_at DESC LIMIT 1`);
    if (!row) {
      this._createActiveKey();
      return this.getActiveSigningKey();
    }
    return {
      kid: row.kid,
      algorithm: row.algorithm,
      publicKeyPem: row.public_key_pem,
      privateKeyPem: decryptWithMaster(settings.masterEncryptionKey, row.private_key_pem),
      activatedAt: row.activated_at,
    };
  }

  getVerificationKeyByKid(kid) {
    const row = database.get(`SELECT * FROM signing_keys WHERE kid = :kid LIMIT 1`, { kid });
    if (!row) {
      return null;
    }
    return {
      kid: row.kid,
      algorithm: row.algorithm,
      status: row.status,
      publicKeyPem: row.public_key_pem,
    };
  }

  rotateSigningKey() {
    this.ensureInitialized();
    const active = database.get(`SELECT id FROM signing_keys WHERE status = 'active' LIMIT 1`);
    if (active) {
      database.run(`UPDATE signing_keys SET status = 'retired', rotated_at = :rotatedAt WHERE id = :id`, {
        rotatedAt: nowIso(),
        id: active.id,
      });
    }
    this._createActiveKey();
    return this.getActiveSigningKey();
  }

  getJwks() {
    this.ensureInitialized();
    const rows = database.all(
      `SELECT kid, algorithm, public_key_pem, status FROM signing_keys WHERE status IN ('active', 'retired') ORDER BY created_at DESC LIMIT 5`
    );

    const keys = rows.map((row) => {
      const keyObject = crypto.createPublicKey(row.public_key_pem);
      const jwk = keyObject.export({ format: 'jwk' });
      return {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        use: 'sig',
        kid: row.kid,
        alg: row.algorithm,
      };
    });

    return { keys };
  }
}

const signingKeyService = new SigningKeyService();
signingKeyService.ensureInitialized();

module.exports = {
  signingKeyService,
};

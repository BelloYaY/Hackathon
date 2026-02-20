const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = process.env.LUCENTID_DB_PATH || path.join(process.cwd(), 'lucentid.db');

class LucentDatabase {
  constructor() {
    const dbDir = path.dirname(DB_PATH);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    this.db = new DatabaseSync(DB_PATH);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.initSchema();
  }

  initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        region TEXT NOT NULL,
        compliance_profile TEXT NOT NULL,
        status TEXT NOT NULL,
        encrypted_dek TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        roles_json TEXT NOT NULL,
        status TEXT NOT NULL,
        assurance_level INTEGER NOT NULL,
        failed_login_count INTEGER NOT NULL,
        last_failed_login_at TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(tenant_id, email),
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS mfa_factors (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        factor_type TEXT NOT NULL,
        secret TEXT NOT NULL,
        is_verified INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        device_name TEXT NOT NULL,
        fingerprint_hash TEXT NOT NULL,
        fingerprint_confidence INTEGER NOT NULL,
        trust_tier TEXT NOT NULL,
        is_approved INTEGER NOT NULL,
        is_compromised INTEGER NOT NULL,
        is_hardware_bound INTEGER NOT NULL,
        public_key_pem TEXT,
        attestation_level TEXT NOT NULL,
        last_seen_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS device_challenges (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
        FOREIGN KEY (device_id) REFERENCES devices(id)
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        state TEXT NOT NULL,
        auth_strength INTEGER NOT NULL,
        trust_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        last_activity_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (device_id) REFERENCES devices(id)
      );

      CREATE TABLE IF NOT EXISTS tokens (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        jti TEXT NOT NULL,
        token_type TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        parent_jti TEXT,
        revoked INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (session_id) REFERENCES sessions(id),
        FOREIGN KEY (device_id) REFERENCES devices(id)
      );

      CREATE TABLE IF NOT EXISTS revocations (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        revocation_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS trust_snapshots (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        trust_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        feature_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS risk_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT,
        severity TEXT NOT NULL,
        event_type TEXT NOT NULL,
        detail_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS behavior_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT,
        event_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        anomaly_score INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS policies (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        status TEXT NOT NULL,
        priority INTEGER NOT NULL,
        rules_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        secret_class TEXT NOT NULL,
        created_by TEXT NOT NULL,
        current_version INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS secret_versions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        secret_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        nonce_b64 TEXT NOT NULL,
        ciphertext_b64 TEXT NOT NULL,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
        FOREIGN KEY (secret_id) REFERENCES secrets(id)
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        actor_id TEXT,
        event_type TEXT NOT NULL,
        action_name TEXT NOT NULL,
        target_id TEXT NOT NULL,
        decision TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        integrity_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS replay_nonces (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        signature TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (tenant_id, nonce),
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS auth_attempts (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT,
        email TEXT NOT NULL,
        success INTEGER NOT NULL,
        ip_address TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
      );

      CREATE TABLE IF NOT EXISTS signing_keys (
        id TEXT PRIMARY KEY,
        kid TEXT NOT NULL UNIQUE,
        algorithm TEXT NOT NULL,
        status TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        created_at TEXT NOT NULL,
        activated_at TEXT NOT NULL,
        rotated_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_users_tenant_status ON users(tenant_id, status);
      CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user ON sessions(tenant_id, user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_tenant_state ON sessions(tenant_id, state);
      CREATE INDEX IF NOT EXISTS idx_tokens_jti ON tokens(jti);
      CREATE INDEX IF NOT EXISTS idx_tokens_tenant_session ON tokens(tenant_id, session_id);
      CREATE INDEX IF NOT EXISTS idx_revocations_tenant_type_target ON revocations(tenant_id, revocation_type, target_id);
      CREATE INDEX IF NOT EXISTS idx_behavior_tenant_user_created ON behavior_events(tenant_id, user_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_risk_tenant_user_created ON risk_events(tenant_id, user_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit_logs(tenant_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_auth_attempt_tenant_email_created ON auth_attempts(tenant_id, email, created_at);
      CREATE INDEX IF NOT EXISTS idx_signing_keys_status ON signing_keys(status, created_at);
    `);
  }

  run(sql, params = {}) {
    return this.db.prepare(sql).run(params);
  }

  get(sql, params = {}) {
    return this.db.prepare(sql).get(params);
  }

  all(sql, params = {}) {
    return this.db.prepare(sql).all(params);
  }

  exec(sql) {
    return this.db.exec(sql);
  }

  close() {
    this.db.close();
  }
}

const database = new LucentDatabase();

module.exports = {
  database,
};

const { database } = require('../database/db');
const { id, nowIso, sha256 } = require('../utils/security');

class AuditService {
  log({ tenantId, actorId = null, eventType, actionName, targetId, decision, metadata = {} }) {
    const previous = database.get(
      `SELECT integrity_hash FROM audit_logs WHERE tenant_id = :tenantId ORDER BY created_at DESC LIMIT 1`,
      { tenantId }
    );
    const previousHash = previous ? previous.integrity_hash : '';
    const createdAt = nowIso();
    const payload = JSON.stringify(
      {
        tenantId,
        actorId,
        eventType,
        actionName,
        targetId,
        decision,
        metadata,
        previousHash,
        createdAt,
      },
      Object.keys({
        tenantId,
        actorId,
        eventType,
        actionName,
        targetId,
        decision,
        metadata,
        previousHash,
        createdAt,
      }).sort()
    );
    const integrityHash = sha256(payload);

    database.run(
      `INSERT INTO audit_logs (id, tenant_id, actor_id, event_type, action_name, target_id, decision, metadata_json, previous_hash, integrity_hash, created_at)
       VALUES (:id, :tenantId, :actorId, :eventType, :actionName, :targetId, :decision, :metadataJson, :previousHash, :integrityHash, :createdAt)`,
      {
        id: id('audit'),
        tenantId,
        actorId,
        eventType,
        actionName,
        targetId,
        decision,
        metadataJson: JSON.stringify(metadata),
        previousHash,
        integrityHash,
        createdAt,
      }
    );

    return integrityHash;
  }

  verifyIntegrity(tenantId) {
    const rows = database.all(
      `SELECT * FROM audit_logs WHERE tenant_id = :tenantId ORDER BY created_at ASC`,
      { tenantId }
    );

    let previousHash = '';
    for (const row of rows) {
      const metadata = JSON.parse(row.metadata_json || '{}');
      const payload = JSON.stringify(
        {
          tenantId: row.tenant_id,
          actorId: row.actor_id,
          eventType: row.event_type,
          actionName: row.action_name,
          targetId: row.target_id,
          decision: row.decision,
          metadata,
          previousHash,
          createdAt: row.created_at,
        },
        Object.keys({
          tenantId: row.tenant_id,
          actorId: row.actor_id,
          eventType: row.event_type,
          actionName: row.action_name,
          targetId: row.target_id,
          decision: row.decision,
          metadata,
          previousHash,
          createdAt: row.created_at,
        }).sort()
      );
      const expectedHash = sha256(payload);
      if (row.previous_hash !== previousHash) {
        return { valid: false, details: `Audit chain broken at ${row.id}` };
      }
      if (row.integrity_hash !== expectedHash) {
        return { valid: false, details: `Audit hash mismatch at ${row.id}` };
      }
      previousHash = row.integrity_hash;
    }

    return { valid: true, details: 'Audit integrity verified' };
  }

  listEvents({ tenantId, limit = 100, offset = 0, eventType = null, actorId = null }) {
    const whereClauses = ['tenant_id = :tenantId'];
    const params = { tenantId, limit, offset };
    if (eventType) {
      whereClauses.push('event_type = :eventType');
      params.eventType = eventType;
    }
    if (actorId) {
      whereClauses.push('actor_id = :actorId');
      params.actorId = actorId;
    }
    const sql = `SELECT * FROM audit_logs WHERE ${whereClauses.join(' AND ')} ORDER BY created_at DESC LIMIT :limit OFFSET :offset`;
    const rows = database.all(sql, params);
    return rows.map((row) => ({
      id: row.id,
      tenant_id: row.tenant_id,
      actor_id: row.actor_id,
      event_type: row.event_type,
      action_name: row.action_name,
      target_id: row.target_id,
      decision: row.decision,
      metadata: JSON.parse(row.metadata_json || '{}'),
      created_at: row.created_at,
      integrity_hash: row.integrity_hash,
      previous_hash: row.previous_hash,
    }));
  }
}

const auditService = new AuditService();

module.exports = {
  auditService,
};

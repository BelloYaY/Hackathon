const { settings } = require('../config/settings');
const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { ConflictError, NotFoundError, UnauthorizedError } = require('../core/errors');
const { id, nowIso, generateTenantDek, encryptTenantDek, decryptTenantDek } = require('../utils/security');

class TenantService {
  bootstrap({ bootstrapKey, tenantId, name, region, complianceProfile }) {
    if (bootstrapKey !== settings.bootstrapAdminKey) {
      throw new UnauthorizedError('Invalid bootstrap key');
    }

    const existing = database.get(`SELECT id FROM tenants WHERE id = :tenantId`, { tenantId });
    if (existing) {
      throw new ConflictError('Tenant already exists');
    }

    const tenantDek = generateTenantDek();
    const encryptedDek = encryptTenantDek(settings.masterEncryptionKey, tenantDek);
    database.run(
      `INSERT INTO tenants (id, name, region, compliance_profile, status, encrypted_dek, created_at)
       VALUES (:id, :name, :region, :complianceProfile, 'active', :encryptedDek, :createdAt)`,
      {
        id: tenantId,
        name,
        region,
        complianceProfile,
        encryptedDek,
        createdAt: nowIso(),
      }
    );

    auditService.log({
      tenantId,
      actorId: null,
      eventType: 'tenant',
      actionName: 'bootstrap',
      targetId: tenantId,
      decision: 'allow',
      metadata: { region, complianceProfile },
    });

    return { id: tenantId, name, region, complianceProfile };
  }

  getTenant(tenantId) {
    const tenant = database.get(`SELECT * FROM tenants WHERE id = :tenantId`, { tenantId });
    if (!tenant) {
      throw new NotFoundError('Tenant not found');
    }
    if (tenant.status !== 'active') {
      throw new UnauthorizedError('Tenant is not active');
    }
    return tenant;
  }

  getTenantDek(tenantId) {
    const tenant = this.getTenant(tenantId);
    return decryptTenantDek(settings.masterEncryptionKey, tenant.encrypted_dek);
  }
}

const tenantService = new TenantService();

module.exports = {
  tenantService,
};

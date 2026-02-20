const { database } = require('../database/db');
const { auditService } = require('../audit/service');
const { ForbiddenError } = require('../core/errors');
const { id, nowIso } = require('../utils/security');

const RISK_LEVEL_ORDER = {
  low: 1,
  guarded: 2,
  elevated: 3,
  high: 4,
  critical: 5,
};

class PolicyService {
  createPolicy({ tenantId, actorId, name, priority = 100, rules }) {
    const policyId = id('pol');
    database.run(
      `INSERT INTO policies (id, tenant_id, name, status, priority, rules_json, created_at)
       VALUES (:id, :tenantId, :name, 'active', :priority, :rulesJson, :createdAt)`,
      {
        id: policyId,
        tenantId,
        name,
        priority,
        rulesJson: JSON.stringify(rules),
        createdAt: nowIso(),
      }
    );
    auditService.log({
      tenantId,
      actorId,
      eventType: 'policy',
      actionName: 'create',
      targetId: policyId,
      decision: 'allow',
      metadata: { name, priority },
    });
    return { policyId, name, priority };
  }

  loadActivePolicies(tenantId) {
    const rows = database.all(
      `SELECT * FROM policies WHERE tenant_id = :tenantId AND status = 'active' ORDER BY priority ASC`,
      { tenantId }
    );
    return rows.map((row) => ({
      ...row,
      rules: JSON.parse(row.rules_json || '{}'),
    }));
  }

  _matchesRule(rule, context) {
    const actionMatch = rule.action === '*' || rule.action === context.action;
    const resourceMatch = rule.resource === '*' || rule.resource === context.resource;
    const roleMatch = !rule.requiredRoles || rule.requiredRoles.some((role) => context.roles.includes(role));
    const trustMatch = rule.minTrust == null || context.trustScore >= rule.minTrust;
    const riskMatch =
      !rule.maxRisk ||
      (RISK_LEVEL_ORDER[context.riskLevel] || 99) <= (RISK_LEVEL_ORDER[rule.maxRisk] || 99);

    return actionMatch && resourceMatch && roleMatch && trustMatch && riskMatch;
  }

  evaluate(context) {
    const reasons = [];
    const constraints = [];

    if (context.riskLevel === 'critical') {
      return { decision: 'deny', reasons: ['risk_critical'], constraints };
    }

    if (context.action.startsWith('admin:') && !context.roles.includes('admin')) {
      return { decision: 'deny', reasons: ['admin_role_required'], constraints };
    }

    if (['policy:write', 'vault:write', 'tenant:admin', 'audit:read', 'token:rotate_key'].includes(context.action) && !context.roles.includes('admin')) {
      return { decision: 'deny', reasons: ['privileged_role_required'], constraints };
    }

    if (context.resourceOwnerId && context.resourceOwnerId !== context.userId && !context.roles.includes('admin')) {
      return { decision: 'deny', reasons: ['resource_owner_mismatch'], constraints };
    }

    const sensitive = ['vault:write', 'policy:write', 'admin:session:lock', 'admin:session:revoke', 'admin:session:unlock', 'token:rotate_key'];
    if (sensitive.includes(context.action) && ['high', 'elevated'].includes(context.riskLevel)) {
      constraints.push('step_up_required');
      reasons.push('risk_based_step_up');
      return { decision: 'step_up', reasons, constraints };
    }

    const policies = this.loadActivePolicies(context.tenantId);
    for (const policy of policies) {
      const ruleList = Array.isArray(policy.rules?.rules) ? policy.rules.rules : [];
      for (const rule of ruleList) {
        if (this._matchesRule(rule, context)) {
          if (rule.effect === 'deny') {
            return { decision: 'deny', reasons: [`policy_deny:${policy.id}`], constraints };
          }
          if (rule.effect === 'step_up') {
            constraints.push('step_up_required');
            return { decision: 'step_up', reasons: [`policy_step_up:${policy.id}`], constraints };
          }
          if (rule.effect === 'allow') {
            reasons.push(`policy_allow:${policy.id}`);
            return { decision: 'allow', reasons, constraints };
          }
        }
      }
    }

    return { decision: 'allow', reasons: reasons.length ? reasons : ['baseline_allow'], constraints };
  }

  requireDecisionAllow(decision) {
    if (decision.decision === 'deny') {
      throw new ForbiddenError(`Access denied: ${decision.reasons.join(',')}`);
    }
    if (decision.decision === 'step_up') {
      throw new ForbiddenError(`Step-up required: ${decision.reasons.join(',')}`);
    }
  }
}

const policyService = new PolicyService();

module.exports = {
  policyService,
};

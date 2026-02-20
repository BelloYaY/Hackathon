import { apiRequest, type ServiceConfig } from '@/services/apiClient';
import type {
  AttackResult,
  AuditEvent,
  AuthProfile,
  BehaviorEvent,
  DeviceSummary,
  PolicyDecision,
  LoginResponse,
  RiskEvent,
  SecurityOverview,
  SessionMe,
  TenantMe,
  TenantSession,
  TokenValidation,
  TrustMe,
  UserDashboardSnapshot,
} from '@/types/lucentid';

export interface LoginInput {
  tenantId: string;
  email: string;
  password: string;
  deviceId: string;
  deviceName?: string;
  otpCode?: string;
}

export interface RegisterInput {
  tenantId: string;
  email: string;
  password: string;
  roles?: string[];
}

export interface BootstrapTenantInput {
  bootstrapKey: string;
  tenantId: string;
  name: string;
  region?: string;
  complianceProfile?: string;
}

export async function health(baseUrl: string) {
  return apiRequest<{ status: string; service: string }>(
    { baseUrl },
    '/health',
    { auth: false }
  );
}

export async function login(baseUrl: string, input: LoginInput) {
  return apiRequest<LoginResponse>(
    { baseUrl },
    '/auth/login',
    {
      method: 'POST',
      auth: false,
      tenantId: input.tenantId,
      body: {
        email: input.email,
        password: input.password,
        device_id: input.deviceId,
        device_name: input.deviceName || 'LucentID Console Device',
        otp_code: input.otpCode,
      },
    }
  );
}

export async function registerUser(baseUrl: string, input: RegisterInput) {
  return apiRequest<{ userId: string; email: string; tenantId: string }>(
    { baseUrl },
    '/auth/register',
    {
      method: 'POST',
      auth: false,
      tenantId: input.tenantId,
      body: {
        email: input.email,
        password: input.password,
        roles: input.roles || ['user'],
      },
    }
  );
}

export async function bootstrapTenant(baseUrl: string, input: BootstrapTenantInput) {
  return apiRequest<{ tenantId: string; name: string; region: string; complianceProfile: string }>(
    { baseUrl },
    '/tenant/bootstrap',
    {
      method: 'POST',
      auth: false,
      headers: {
        'x-bootstrap-key': input.bootstrapKey,
      },
      body: {
        tenant_id: input.tenantId,
        name: input.name,
        region: input.region || 'us',
        compliance_profile: input.complianceProfile || 'standard',
      },
    }
  );
}

export async function getAuthProfile(config: ServiceConfig) {
  return apiRequest<AuthProfile>(config, '/auth/me');
}

export async function getSessionMe(config: ServiceConfig) {
  return apiRequest<SessionMe>(config, '/session/me');
}

export async function getTrustMe(config: ServiceConfig, headers?: Record<string, string>) {
  return apiRequest<TrustMe>(config, '/trust/me', {
    headers,
  });
}

export async function evaluatePolicyDecision(
  config: ServiceConfig,
  body: { action: string; resource: string; resource_owner_id?: string | null }
) {
  return apiRequest<PolicyDecision>(config, '/policy/evaluate', {
    method: 'POST',
    body: {
      action: body.action,
      resource: body.resource,
      resource_owner_id: body.resource_owner_id ?? null,
    },
  });
}

export async function getMyDevices(config: ServiceConfig) {
  return apiRequest<DeviceSummary[]>(config, '/device');
}

export async function bindDeviceHardwareKey(
  config: ServiceConfig,
  deviceId: string,
  publicKeyPem: string,
  attestationLevel = 'attested'
) {
  return apiRequest<{ id: string; is_hardware_bound: boolean; attestation_level: string }>(
    config,
    `/device/${encodeURIComponent(deviceId)}/hardware-key`,
    {
      method: 'POST',
      body: {
        public_key_pem: publicKeyPem,
        attestation_level: attestationLevel,
      },
    }
  );
}

export async function createDeviceChallenge(config: ServiceConfig, deviceId: string) {
  return apiRequest<{ challenge_id: string; nonce: string; expires_at: string }>(
    config,
    `/device/${encodeURIComponent(deviceId)}/challenge`,
    {
      method: 'POST',
      body: {},
    }
  );
}

export async function attestDeviceChallenge(
  config: ServiceConfig,
  deviceId: string,
  challengeId: string,
  signatureB64: string
) {
  return apiRequest<{ id: string; trust_tier: string; is_hardware_bound: boolean }>(
    config,
    `/device/${encodeURIComponent(deviceId)}/attest`,
    {
      method: 'POST',
      body: {
        challenge_id: challengeId,
        signature_b64: signatureB64,
      },
    }
  );
}

export async function getTenant(config: ServiceConfig) {
  return apiRequest<TenantMe>(config, '/tenant/me', {
    auth: false,
    tenantId: config.tenantId,
  });
}

export async function validateToken(config: ServiceConfig) {
  if (!config.accessToken || !config.deviceId) {
    return null;
  }

  return apiRequest<TokenValidation>(config, '/token/validate', {
    method: 'POST',
    auth: false,
    tenantId: config.tenantId,
    signed: true,
    body: {
      token: config.accessToken,
      device_id: config.deviceId,
    },
  });
}

export async function logout(config: ServiceConfig) {
  return apiRequest<{ session_id: string; state: string; revoked_tokens: number }>(config, '/auth/logout', {
    method: 'POST',
    body: {},
  });
}

export async function getSecurityOverview(config: ServiceConfig) {
  return apiRequest<SecurityOverview>(config, '/monitor/security-overview');
}

export async function getRiskEvents(config: ServiceConfig, limit = 50) {
  return apiRequest<RiskEvent[]>(config, `/monitor/risk-events?limit=${limit}`);
}

export async function getBehaviorEvents(config: ServiceConfig, limit = 50) {
  return apiRequest<BehaviorEvent[]>(config, `/monitor/behavior-events?limit=${limit}`);
}

export async function getAuditEvents(config: ServiceConfig, limit = 100) {
  return apiRequest<AuditEvent[]>(config, `/audit/events?limit=${limit}`);
}

export async function getSessions(config: ServiceConfig, limit = 100) {
  return apiRequest<TenantSession[]>(config, `/session?limit=${limit}`);
}

export async function getAuditIntegrity(config: ServiceConfig) {
  return apiRequest<{ valid: boolean; details: string }>(config, '/audit/integrity');
}

export async function createVaultSecret(
  config: ServiceConfig,
  body: { name: string; value: string; secret_class?: 'standard' | 'critical' },
  headers?: Record<string, string>
) {
  return apiRequest<{ id: string; name: string }>(config, '/vault/secrets', {
    method: 'POST',
    headers,
    signed: !headers,
    body,
  });
}

export async function fetchUserDashboardSnapshot(config: ServiceConfig): Promise<UserDashboardSnapshot> {
  const [profile, session, trust, tenant, devices, token] = await Promise.all([
    getAuthProfile(config),
    getSessionMe(config),
    getTrustMe(config),
    getTenant(config),
    getMyDevices(config),
    validateToken(config).catch(() => null),
  ]);

  return {
    profile,
    session,
    trust,
    tenant,
    devices,
    token,
  };
}

export type { ServiceConfig, AttackResult };

import { createSignedHeaders } from '@/lib/signature';
import { randomId } from '@/lib/utils';
import { ApiError, apiRequest, type ServiceConfig } from '@/services/apiClient';
import {
  getAuditEvents,
  getBehaviorEvents,
  getRiskEvents,
  getSessionMe,
  getTrustMe,
  login,
  registerUser,
} from '@/services/lucentidService';
import type { AttackResult, LoginResponse } from '@/types/lucentid';

const ATTACK_PASSWORD = 'Str0ng!Password#1';

function scenarioConfig(baseUrl: string, tenantId: string, loginRes: LoginResponse, deviceId: string, signatureSecret?: string): ServiceConfig {
  return {
    baseUrl,
    tenantId,
    deviceId,
    accessToken: loginRes.access_token,
    refreshToken: loginRes.refresh_token,
    signatureSecret,
  };
}

async function createScenarioUser(baseUrl: string, tenantId: string, role: 'user' | 'admin', prefix: string) {
  const email = `${prefix}.${Date.now()}@lucentid.local`;
  await registerUser(baseUrl, {
    tenantId,
    email,
    password: ATTACK_PASSWORD,
    roles: [role],
  });
  return email;
}

async function loginScenarioUser(baseUrl: string, tenantId: string, email: string, deviceId: string) {
  return login(baseUrl, {
    tenantId,
    email,
    password: ATTACK_PASSWORD,
    deviceId,
    deviceName: `Scenario-${deviceId}`,
  });
}

async function didRiskAlertFire(operatorConfig: ServiceConfig | null, eventType: string, startedAt: number) {
  if (!operatorConfig) {
    return false;
  }

  try {
    const events = await getRiskEvents(operatorConfig, 40);
    return events.some((event) => event.event_type === eventType && new Date(event.created_at).getTime() >= startedAt - 1000);
  } catch {
    return false;
  }
}

async function didBehaviorAlertFire(operatorConfig: ServiceConfig | null, startedAt: number, minScore = 70) {
  if (!operatorConfig) {
    return false;
  }

  try {
    const events = await getBehaviorEvents(operatorConfig, 40);
    return events.some((event) => event.anomaly_score >= minScore && new Date(event.created_at).getTime() >= startedAt - 1000);
  } catch {
    return false;
  }
}

async function didAuthAlertFire(operatorConfig: ServiceConfig | null, email: string, startedAt: number) {
  if (!operatorConfig) {
    return false;
  }
  try {
    const events = await getAuditEvents(operatorConfig, 80);
    return events.some(
      (event) =>
        event.event_type === 'auth' &&
        event.action_name === 'login' &&
        event.decision === 'deny' &&
        event.target_id === email &&
        new Date(event.created_at).getTime() >= startedAt - 1000
    );
  } catch {
    return false;
  }
}

export async function runSessionHijackScenario(baseUrl: string, tenantId: string, operatorConfig: ServiceConfig | null): Promise<AttackResult> {
  const startedAt = Date.now();
  const email = await createScenarioUser(baseUrl, tenantId, 'user', 'hijack');
  const deviceId = randomId('hijack-device');
  const userLogin = await loginScenarioUser(baseUrl, tenantId, email, deviceId);
  const userConfig = scenarioConfig(baseUrl, tenantId, userLogin, deviceId);

  const trustBefore = await getTrustMe(userConfig);

  let statusCode = 200;
  let detail = 'allowed';
  try {
    await getTrustMe(userConfig, {
      'x-forwarded-for': '203.0.113.77',
    });
    statusCode = 200;
    detail = 'hijack request unexpectedly allowed';
  } catch (error) {
    const apiError = error as ApiError;
    statusCode = apiError.status;
    detail = apiError.message;
  }

  let sessionStateAfter = 'unknown';
  try {
    const session = await getSessionMe(userConfig);
    sessionStateAfter = session.state;
  } catch (error) {
    const apiError = error as ApiError;
    sessionStateAfter = apiError.status === 403 ? 'locked' : 'invalid_or_revoked';
  }

  const alertTriggered =
    (await didRiskAlertFire(operatorConfig, 'session_hijacking_detected', startedAt)) ||
    (await didBehaviorAlertFire(operatorConfig, startedAt));

  return {
    scenario: 'session_hijack',
    status_code: statusCode,
    blocked: statusCode >= 400,
    allowed: statusCode < 400,
    trust_before: trustBefore.trust_score,
    trust_after: undefined,
    session_state_after: sessionStateAfter,
    alert_triggered: alertTriggered,
    detail,
    recorded_at: new Date().toISOString(),
  };
}

export async function runReplayAttackScenario(
  baseUrl: string,
  tenantId: string,
  operatorConfig: ServiceConfig | null,
  signatureSecret: string
): Promise<AttackResult> {
  const startedAt = Date.now();
  const email = await createScenarioUser(baseUrl, tenantId, 'admin', 'replay');
  const deviceId = randomId('replay-device');
  const userLogin = await loginScenarioUser(baseUrl, tenantId, email, deviceId);
  const userConfig = scenarioConfig(baseUrl, tenantId, userLogin, deviceId, signatureSecret);

  const trustBefore = await getTrustMe(userConfig);

  const requestBody = {
    name: randomId('replay-secret'),
    value: `secret-${Date.now()}`,
    secret_class: 'standard' as const,
  };
  const nonce = randomId('replay-nonce');
  const timestamp = `${Date.now()}`;
  const signedHeaders = await createSignedHeaders(signatureSecret, requestBody, nonce, timestamp);

  await apiRequest(userConfig, '/vault/secrets', {
    method: 'POST',
    headers: signedHeaders,
    body: requestBody,
  });

  let statusCode = 200;
  let detail = 'allowed';
  try {
    await apiRequest(userConfig, '/vault/secrets', {
      method: 'POST',
      headers: signedHeaders,
      body: requestBody,
    });
  } catch (error) {
    const apiError = error as ApiError;
    statusCode = apiError.status;
    detail = apiError.message;
  }

  const trustAfter = await getTrustMe(userConfig);
  const alertTriggered =
    statusCode === 409 ||
    (await didBehaviorAlertFire(operatorConfig, startedAt));

  return {
    scenario: 'replay_attack',
    status_code: statusCode,
    blocked: statusCode >= 400,
    allowed: statusCode < 400,
    trust_before: trustBefore.trust_score,
    trust_after: trustAfter.trust_score,
    session_state_after: 'active',
    alert_triggered: alertTriggered,
    detail,
    recorded_at: new Date().toISOString(),
  };
}

export async function runDeviceImpersonationScenario(baseUrl: string, tenantId: string, operatorConfig: ServiceConfig | null): Promise<AttackResult> {
  const startedAt = Date.now();
  const email = await createScenarioUser(baseUrl, tenantId, 'user', 'device-imp');
  const legitDeviceId = randomId('legit-device');
  const attackerDeviceId = randomId('attacker-device');

  const userLogin = await loginScenarioUser(baseUrl, tenantId, email, legitDeviceId);
  const userConfig = scenarioConfig(baseUrl, tenantId, userLogin, legitDeviceId);

  const trustBefore = await getTrustMe(userConfig);

  let statusCode = 200;
  let detail = 'allowed';
  try {
    await apiRequest(userConfig, '/trust/me', {
      deviceId: attackerDeviceId,
    });
  } catch (error) {
    const apiError = error as ApiError;
    statusCode = apiError.status;
    detail = apiError.message;
  }

  let sessionStateAfter = 'unknown';
  try {
    const session = await getSessionMe(userConfig);
    sessionStateAfter = session.state;
  } catch {
    sessionStateAfter = 'revoked_or_invalid';
  }

  const alertTriggered =
    (await didRiskAlertFire(operatorConfig, 'token_theft_detected', startedAt)) ||
    (await didBehaviorAlertFire(operatorConfig, startedAt));

  return {
    scenario: 'device_impersonation',
    status_code: statusCode,
    blocked: statusCode >= 400,
    allowed: statusCode < 400,
    trust_before: trustBefore.trust_score,
    trust_after: undefined,
    session_state_after: sessionStateAfter,
    alert_triggered: alertTriggered,
    detail,
    recorded_at: new Date().toISOString(),
  };
}

export async function runAuthenticationAttackScenario(baseUrl: string, tenantId: string, operatorConfig: ServiceConfig | null): Promise<AttackResult> {
  const startedAt = Date.now();
  const email = await createScenarioUser(baseUrl, tenantId, 'user', 'auth-burst');

  let finalStatus = 0;
  let sawAdaptiveLockout = false;
  let sawRateLimit = false;
  for (let index = 0; index < 6; index += 1) {
    try {
      await apiRequest(
        { baseUrl },
        '/auth/login',
        {
          method: 'POST',
          auth: false,
          tenantId,
          body: {
            email,
            password: 'Wrong!Password#1',
            device_id: randomId(`auth-attack-${index}`),
          },
        }
      );
      finalStatus = 200;
    } catch (error) {
      const status = (error as ApiError).status;
      finalStatus = status;
      if (status === 403) {
        sawAdaptiveLockout = true;
      }
      if (status === 429) {
        sawRateLimit = true;
      }
    }
  }

  const alertTriggered = await didAuthAlertFire(operatorConfig, email, startedAt);
  const blocked = finalStatus >= 400;

  let detail = 'Authentication burst not blocked';
  if (sawAdaptiveLockout) {
    detail = 'Adaptive lockout triggered';
  } else if (sawRateLimit) {
    detail = 'Rate limiter blocked authentication burst';
  } else if (blocked) {
    detail = 'Authentication burst blocked';
  }

  return {
    scenario: 'authentication_attack',
    status_code: finalStatus,
    blocked,
    allowed: !blocked,
    trust_before: undefined,
    trust_after: undefined,
    session_state_after: 'n/a',
    alert_triggered: alertTriggered,
    detail,
    recorded_at: new Date().toISOString(),
  };
}

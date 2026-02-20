export type RiskLevel = 'low' | 'guarded' | 'elevated' | 'high' | 'critical';

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  session_id: string;
  trust_score: number;
  risk_level: RiskLevel;
  user: {
    id: string;
    email: string;
    tenant_id: string;
    roles: string[];
  };
}

export interface AuthProfile {
  id: string;
  email: string;
  tenant_id: string;
  roles: string[];
  session_id: string;
  trust_score: number;
  risk_level: RiskLevel;
  auth_strength: number;
}

export interface SessionMe {
  id: string;
  state: string;
  trust_score: number;
  risk_level: RiskLevel;
  last_activity_at: string;
  expires_at: string;
}

export interface TrustMe {
  trust_score: number;
  risk_level: RiskLevel;
  reasons: string[];
}

export interface PolicyDecision {
  decision: 'allow' | 'step_up' | 'deny';
  reasons: string[];
  constraints: string[];
}

export interface DeviceSummary {
  id: string;
  trust_tier: string;
  is_approved: boolean;
  is_hardware_bound: boolean;
}

export interface TokenValidation {
  active: boolean;
  reason?: string;
  subject?: string;
  tenant_id?: string;
  session_id?: string;
  claims?: Record<string, unknown>;
}

export interface TenantMe {
  id: string;
  name: string;
  region: string;
  compliance_profile: string;
  status: string;
}

export interface SecurityOverview {
  tenant_id: string;
  active_sessions: number;
  high_risk_events_24h: number;
  high_anomaly_events_24h: number;
  revoked_tokens_total: number;
}

export interface RiskEvent {
  id: string;
  user_id: string;
  session_id: string | null;
  severity: string;
  event_type: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface BehaviorEvent {
  id: string;
  user_id: string;
  session_id: string | null;
  event_type: string;
  anomaly_score: number;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  tenant_id: string;
  actor_id: string | null;
  event_type: string;
  action_name: string;
  target_id: string;
  decision: string;
  metadata: Record<string, unknown>;
  created_at: string;
  integrity_hash: string;
  previous_hash: string;
}

export interface TenantSession {
  id: string;
  user_id: string;
  user_email: string;
  device_id: string;
  state: string;
  auth_strength: number;
  trust_score: number;
  risk_level: RiskLevel;
  ip_address: string;
  user_agent: string;
  last_activity_at: string;
  expires_at: string;
  created_at: string;
}

export interface AttackResult {
  scenario: 'session_hijack' | 'replay_attack' | 'device_impersonation' | 'authentication_attack';
  status_code: number;
  blocked: boolean;
  allowed: boolean;
  trust_before?: number;
  trust_after?: number;
  session_state_after?: string;
  alert_triggered: boolean;
  detail: string;
  recorded_at: string;
}

export interface UserDashboardSnapshot {
  profile: AuthProfile;
  session: SessionMe;
  trust: TrustMe;
  tenant: TenantMe;
  devices: DeviceSummary[];
  token: TokenValidation | null;
}

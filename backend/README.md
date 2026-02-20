# LucentID Core

LucentID Core is a Zero Trust Identity Platform implemented in Node.js with multi-tenant isolation, continuous trust/risk evaluation, policy-based enforcement, secret vaulting, and enterprise token validation.

## Core Capabilities
- Identity authentication with password policy and adaptive lockout.
- MFA enrollment and verification (TOTP).
- Trusted device registration, approval, revocation, and hardware-bound attestation challenge.
- Session lifecycle controls (create, validate, lock, unlock, revoke, revoke-all).
- Access/refresh token lifecycle with revocation and refresh-rotation.
- Asymmetric JWT signing (`RS256`) with key rotation and JWKS exposure.
- Trust score + risk classification with behavior-anomaly triggers.
- Policy-based authorization with dynamic deny and step-up decisions.
- Secret vault with tenant-scoped encryption and secret rotation.
- Audit hash-chained event logs with integrity verification.
- Monitoring endpoints for SOC-style risk/behavior visibility.
- Replay protection and request signing on high-risk endpoints.

## Start
```powershell
cd s:\Hackathon\backend
npm install
npm start
```

Server default: `http://localhost:3000`

## Run Tests
```powershell
cd s:\Hackathon\backend
npm test
```

## API Base
`/api/v1`

## Key Integration Endpoints (Finance App)
- Health: `GET /api/v1/health`
- Enterprise token validation: `POST /api/v1/token/validate`
- JWKS for verifier caches: `GET /api/v1/token/jwks`
- Auth login: `POST /api/v1/auth/login`
- Auth profile: `GET /api/v1/auth/me`
- Auth logout: `POST /api/v1/auth/logout`
- Auth logout all: `POST /api/v1/auth/logout-all`
- Trust posture: `GET /api/v1/trust/me`
- Admin session list: `GET /api/v1/session`
- Session controls: `POST /api/v1/session/:id/lock|unlock|revoke`
- Admin device list: `GET /api/v1/device/all`
- Audit integrity: `GET /api/v1/audit/integrity`
- Monitoring overview: `GET /api/v1/monitor/security-overview`

## Security Notes
- Private signing keys and tenant DEKs are encrypted with platform master key material.
- Tokens are bound to device context and tenant context.
- Signed-request + nonce replay protection is enforced on sensitive endpoints.
- All privileged actions are audited with tamper-evident chain links.

## External Production Prerequisites
For full enterprise deployment, pair this codebase with:
- HSM/KMS-backed key custody and rotation orchestration.
- mTLS service mesh/workload identity.
- SIEM export pipeline and long-term immutable log archive.
- HA/DR deployment with regional failover.
- WAF/DDOS and infrastructure hardening controls.

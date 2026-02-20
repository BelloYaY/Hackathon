const express = require('express');

const { requireTenant } = require('../middleware/tenant');
const { requireAuth } = require('../middleware/auth');
const { deviceService } = require('../device/service');
const { ValidationError } = require('../core/errors');

const deviceRouter = express.Router();

deviceRouter.get(
  '/all',
  requireTenant,
  requireAuth({ action: 'admin:device:list', resource: 'device' }),
  (req, res, next) => {
    try {
      const limit = Math.min(Number(req.query.limit || 100), 500);
      const offset = Math.max(Number(req.query.offset || 0), 0);
      const devices = deviceService.listTenantDevices({
        tenantId: req.tenantId,
        limit,
        offset,
      });
      res.json(
        devices.map((d) => ({
          id: d.id,
          user_id: d.user_id,
          user_email: d.user_email,
          device_name: d.device_name,
          trust_tier: d.trust_tier,
          is_approved: !!d.is_approved,
          is_compromised: !!d.is_compromised,
          is_hardware_bound: !!d.is_hardware_bound,
          attestation_level: d.attestation_level,
          last_seen_at: d.last_seen_at,
          created_at: d.created_at,
        }))
      );
    } catch (err) {
      next(err);
    }
  }
);

deviceRouter.get(
  '/',
  requireTenant,
  requireAuth({ action: 'device:list', resource: 'device' }),
  (req, res, next) => {
    try {
      const devices = deviceService.listUserDevices({
        tenantId: req.tenantId,
        userId: req.securityContext.userId,
      });
      res.json(devices.map((d) => ({
        id: d.id,
        trust_tier: d.trust_tier,
        is_approved: !!d.is_approved,
        is_hardware_bound: !!d.is_hardware_bound,
      })));
    } catch (err) {
      next(err);
    }
  }
);

deviceRouter.post(
  '/:deviceId/approve',
  requireTenant,
  requireAuth({ action: 'admin:device:approve', resource: 'device' }),
  (req, res, next) => {
    try {
      const device = deviceService.approveDevice({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        deviceId: req.params.deviceId,
      });
      res.json({ id: device.id, trust_tier: device.trust_tier, is_approved: !!device.is_approved });
    } catch (err) {
      next(err);
    }
  }
);

deviceRouter.post(
  '/:deviceId/revoke',
  requireTenant,
  requireAuth({ action: 'admin:device:revoke', resource: 'device' }),
  (req, res, next) => {
    try {
      const reason = req.body?.reason || 'manual_revoke';
      const device = deviceService.revokeDevice({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        deviceId: req.params.deviceId,
        reason,
      });
      res.json({ id: device.id, trust_tier: device.trust_tier, is_approved: !!device.is_approved });
    } catch (err) {
      next(err);
    }
  }
);

deviceRouter.post(
  '/:deviceId/hardware-key',
  requireTenant,
  requireAuth({ action: 'device:hardware_bind', resource: 'device' }),
  (req, res, next) => {
    try {
      const { public_key_pem: publicKeyPem, attestation_level: attestationLevel = 'attested' } = req.body || {};
      if (!publicKeyPem) {
        throw new ValidationError('public_key_pem is required');
      }
      const device = deviceService.registerHardwareKey({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        deviceId: req.params.deviceId,
        publicKeyPem,
        attestationLevel,
      });
      res.json({ id: device.id, is_hardware_bound: !!device.is_hardware_bound, attestation_level: device.attestation_level });
    } catch (err) {
      next(err);
    }
  }
);

deviceRouter.post(
  '/:deviceId/challenge',
  requireTenant,
  requireAuth({ action: 'device:hardware_challenge', resource: 'device' }),
  (req, res, next) => {
    try {
      const challenge = deviceService.createChallenge({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        deviceId: req.params.deviceId,
      });
      res.status(201).json({
        challenge_id: challenge.challengeId,
        nonce: challenge.nonce,
        expires_at: challenge.expiresAt,
      });
    } catch (err) {
      next(err);
    }
  }
);

deviceRouter.post(
  '/:deviceId/attest',
  requireTenant,
  requireAuth({ action: 'device:hardware_attest', resource: 'device' }),
  (req, res, next) => {
    try {
      const { challenge_id: challengeId, signature_b64: signatureB64 } = req.body || {};
      if (!challengeId || !signatureB64) {
        throw new ValidationError('challenge_id and signature_b64 are required');
      }
      const device = deviceService.attestChallenge({
        tenantId: req.tenantId,
        actorId: req.securityContext.userId,
        deviceId: req.params.deviceId,
        challengeId,
        signatureB64,
      });
      res.json({ id: device.id, trust_tier: device.trust_tier, is_hardware_bound: !!device.is_hardware_bound });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = {
  deviceRouter,
};

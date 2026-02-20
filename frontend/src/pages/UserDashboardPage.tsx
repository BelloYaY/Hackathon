import { useCallback, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, ShieldCheck, Sparkles, Wallet } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { MetricCard } from '@/components/shared/MetricCard';
import { RiskBadge } from '@/components/shared/RiskBadge';
import { TrustScore } from '@/components/shared/TrustScore';
import { Button } from '@/components/ui/button';
import { usePolling } from '@/hooks/usePolling';
import { useAuth } from '@/hooks/useAuth';
import {
  attestDeviceChallenge,
  bindDeviceHardwareKey,
  createDeviceChallenge,
  evaluatePolicyDecision,
  fetchUserDashboardSnapshot,
  login as loginRequest,
} from '@/services/lucentidService';
import { ApiError } from '@/services/apiClient';
import { formatTime, shortId } from '@/lib/utils';
import type { UserDashboardSnapshot } from '@/types/lucentid';

interface ActionResult {
  id: string;
  title: string;
  detail: string;
  trustDelta: number;
  at: string;
}

function formatDecision(decision: 'allow' | 'step_up' | 'deny') {
  if (decision === 'allow') {
    return 'Allowed';
  }
  if (decision === 'step_up') {
    return 'Step-up required';
  }
  return 'Blocked';
}

function arrayBufferToBase64(buffer: ArrayBuffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < bytes.byteLength; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}

function toPem(label: string, der: ArrayBuffer) {
  const base64 = arrayBufferToBase64(der);
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

export function UserDashboardPage() {
  const { serviceConfig, session } = useAuth();
  const navigate = useNavigate();
  const isAdmin = !!session?.roles?.includes('admin');

  const [snapshot, setSnapshot] = useState<UserDashboardSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionRunning, setActionRunning] = useState<'bill-pay' | 'send-money' | 'secure-device' | 'failed-auth' | null>(
    null
  );
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionResults, setActionResults] = useState<ActionResult[]>([]);

  const commitSnapshot = useCallback((data: UserDashboardSnapshot) => {
    setSnapshot(data);
    setError(null);
  }, []);

  const fetchSnapshot = useCallback(async () => {
    try {
      const data = await fetchUserDashboardSnapshot(serviceConfig);
      commitSnapshot(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Unable to load dashboard data');
      }
    }
  }, [commitSnapshot, serviceConfig]);

  usePolling(fetchSnapshot, 4000, !!serviceConfig.accessToken);

  const currentDevice = useMemo(() => {
    if (!snapshot || !session) return null;
    return snapshot.devices.find((device) => device.id === session.deviceId) || snapshot.devices[0] || null;
  }, [session, snapshot]);

  const appendActionResult = useCallback((result: ActionResult) => {
    setActionResults((prev) => [result, ...prev].slice(0, 6));
  }, []);

  const runBillPayAction = useCallback(async () => {
    setActionMessage(null);
    setActionRunning('bill-pay');
    try {
      const before = snapshot?.trust?.trust_score ?? 0;
      const decision = await evaluatePolicyDecision(serviceConfig, {
        action: 'payment:bill_pay',
        resource: 'payment',
        resource_owner_id: session?.userId || null,
      });
      const data = await fetchUserDashboardSnapshot(serviceConfig);
      commitSnapshot(data);
      const delta = data.trust.trust_score - before;
      setActionMessage(`Bill pay ${formatDecision(decision.decision)}. Trust ${delta >= 0 ? '+' : ''}${delta}.`);
      appendActionResult({
        id: `bill-pay-${Date.now()}`,
        title: 'Pay Utility Bill ($120)',
        detail: `${formatDecision(decision.decision)} by backend policy evaluation.`,
        trustDelta: delta,
        at: new Date().toISOString(),
      });
    } catch (err) {
      setActionMessage(err instanceof Error ? err.message : 'Bill payment check failed');
    } finally {
      setActionRunning(null);
    }
  }, [appendActionResult, commitSnapshot, serviceConfig, session?.userId, snapshot?.trust?.trust_score]);

  const runSendMoneyAction = useCallback(async () => {
    setActionMessage(null);
    setActionRunning('send-money');
    try {
      const before = snapshot?.trust?.trust_score ?? 0;
      const decision = await evaluatePolicyDecision(serviceConfig, {
        action: 'payment:send_money_sensitive',
        resource: 'transfer',
        resource_owner_id: session?.userId || null,
      });
      const data = await fetchUserDashboardSnapshot(serviceConfig);
      commitSnapshot(data);
      const delta = data.trust.trust_score - before;
      setActionMessage(`Send money ${formatDecision(decision.decision)}. Trust ${delta >= 0 ? '+' : ''}${delta}.`);
      appendActionResult({
        id: `send-money-${Date.now()}`,
        title: 'Send Money ($5,000)',
        detail: `${formatDecision(decision.decision)} by backend policy evaluation.`,
        trustDelta: delta,
        at: new Date().toISOString(),
      });
    } catch (err) {
      setActionMessage(err instanceof Error ? err.message : 'Transfer check failed');
    } finally {
      setActionRunning(null);
    }
  }, [appendActionResult, commitSnapshot, serviceConfig, session?.userId, snapshot?.trust?.trust_score]);

  const runFailedTransferAuthorizationAction = useCallback(async () => {
    if (!session) {
      setActionMessage('No active user session found.');
      return;
    }

    setActionMessage(null);
    setActionRunning('failed-auth');

    try {
      const before = snapshot?.trust?.trust_score ?? 0;
      let failureMessage = 'Transfer confirmation failed';
      try {
        await loginRequest(serviceConfig.baseUrl, {
          tenantId: session.tenantId,
          email: session.email,
          password: 'Wrong!TransferPass#1',
          deviceId: session.deviceId,
          deviceName: 'Transfer Confirmation',
        });
        failureMessage = 'Unexpectedly allowed';
      } catch (err) {
        if (err instanceof ApiError) {
          failureMessage = err.message;
        } else if (err instanceof Error) {
          failureMessage = err.message;
        }
      }

      const data = await fetchUserDashboardSnapshot(serviceConfig);
      commitSnapshot(data);
      const delta = data.trust.trust_score - before;
      setActionMessage(`${failureMessage}. Trust ${delta >= 0 ? '+' : ''}${delta}.`);
      appendActionResult({
        id: `failed-auth-${Date.now()}`,
        title: 'Transfer Confirmation (Wrong Password)',
        detail: 'Recorded a failed auth attempt through real backend login logic.',
        trustDelta: delta,
        at: new Date().toISOString(),
      });
    } catch (err) {
      setActionMessage(err instanceof Error ? err.message : 'Failed transfer confirmation simulation failed');
    } finally {
      setActionRunning(null);
    }
  }, [appendActionResult, commitSnapshot, serviceConfig, session, snapshot?.trust?.trust_score]);

  const runSecureDeviceAction = useCallback(async () => {
    if (!session?.deviceId) {
      setActionMessage('No active device found for this session.');
      return;
    }
    if (!window.crypto?.subtle) {
      setActionMessage('WebCrypto is not available in this browser.');
      return;
    }

    setActionMessage(null);
    setActionRunning('secure-device');

    try {
      const before = snapshot?.trust?.trust_score ?? 0;
      const keyPair = (await window.crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,
        ['sign', 'verify']
      )) as CryptoKeyPair;

      const publicDer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
      const publicPem = toPem('PUBLIC KEY', publicDer);

      await bindDeviceHardwareKey(serviceConfig, session.deviceId, publicPem, 'attested');
      const challenge = await createDeviceChallenge(serviceConfig, session.deviceId);

      const signatureBuffer = await window.crypto.subtle.sign(
        { name: 'Ed25519' },
        keyPair.privateKey,
        new TextEncoder().encode(challenge.nonce)
      );
      const signatureB64 = arrayBufferToBase64(signatureBuffer);
      await attestDeviceChallenge(serviceConfig, session.deviceId, challenge.challenge_id, signatureB64);

      const data = await fetchUserDashboardSnapshot(serviceConfig);
      commitSnapshot(data);
      const delta = data.trust.trust_score - before;
      setActionMessage(`Device secured. Trust ${delta >= 0 ? '+' : ''}${delta}.`);
      appendActionResult({
        id: `secure-${Date.now()}`,
        title: 'Secure Device for Large Transfers',
        detail: 'Completed hardware-key binding + challenge attestation.',
        trustDelta: delta,
        at: new Date().toISOString(),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Device verification failed';
      setActionMessage(message);
    } finally {
      setActionRunning(null);
    }
  }, [appendActionResult, commitSnapshot, serviceConfig, session?.deviceId, snapshot?.trust?.trust_score]);

  const quickActionsCard = (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wallet className="h-4 w-4 text-primary" />
          Quick Actions
        </CardTitle>
        <CardDescription>Simple actions for the demo. All call real backend logic.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 p-3">
          <div>
            <div className="text-sm font-medium">Pay Utility Bill ($120)</div>
            <div className="text-xs text-muted-foreground">Standard payment policy check.</div>
          </div>
          <Button size="sm" variant="outline" onClick={runBillPayAction} disabled={!!actionRunning}>
            {actionRunning === 'bill-pay' ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : null}
            Run
          </Button>
        </div>

        <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 p-3">
          <div>
            <div className="text-sm font-medium">Send Money ($5,000)</div>
            <div className="text-xs text-muted-foreground">Sensitive transfer policy check.</div>
          </div>
          <Button size="sm" variant="outline" onClick={runSendMoneyAction} disabled={!!actionRunning}>
            {actionRunning === 'send-money' ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : null}
            Run
          </Button>
        </div>

        <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 p-3">
          <div>
            <div className="text-sm font-medium">Secure Device</div>
            <div className="text-xs text-muted-foreground">Hardware-key bind + challenge + attest.</div>
          </div>
          <Button size="sm" variant="outline" onClick={runSecureDeviceAction} disabled={!!actionRunning}>
            {actionRunning === 'secure-device' ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : null}
            Run
          </Button>
        </div>

        <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 p-3">
          <div>
            <div className="text-sm font-medium">Transfer Confirmation (Wrong Password)</div>
            <div className="text-xs text-muted-foreground">Generates real failed-auth signal.</div>
          </div>
          <Button size="sm" variant="outline" onClick={runFailedTransferAuthorizationAction} disabled={!!actionRunning}>
            {actionRunning === 'failed-auth' ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : null}
            Run
          </Button>
        </div>

        {actionMessage ? (
          <div className="rounded-md border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">
            {actionMessage}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );

  return (
    <div className="space-y-4">
      <Card className="overflow-hidden">
        <CardContent className="p-0">
          <div className="bg-gradient-to-r from-cyan-500/20 via-blue-500/10 to-transparent p-5">
            <div className="grid gap-4 md:grid-cols-[1.3fr_1fr]">
              <div>
                <div className="mb-2 inline-flex items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-xs text-cyan-200">
                  <Sparkles className="h-3.5 w-3.5" />
                  {isAdmin ? 'Admin Dashboard' : 'User Dashboard'}
                </div>
                <h2 className="text-xl font-semibold tracking-tight">
                  {isAdmin ? 'Security Demo Control View' : 'Simple Banking Demo View'}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">{snapshot?.profile.email || session?.email || '-'}</p>
                <p className="mt-3 text-xs text-muted-foreground">
                  Keep the flow simple: run one action, watch decision, then check trust impact.
                </p>
              </div>

              <div className="rounded-md border border-white/15 bg-black/20 p-3 text-xs">
                <div className="mb-2 font-medium text-foreground">Demo Steps</div>
                <div className="space-y-1 text-muted-foreground">
                  <div>1. Run a quick action.</div>
                  <div>2. Read the action result.</div>
                  <div>3. Check trust/risk metrics update.</div>
                </div>
                {isAdmin ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button onClick={() => navigate('/simulator?autorun=1')} variant="outline" size="sm">
                      Run Full Demo
                    </Button>
                    <Button onClick={() => navigate('/simulator')} variant="outline" size="sm">
                      Open Simulator
                    </Button>
                    <Button onClick={() => navigate('/soc')} variant="outline" size="sm">
                      Open SOC
                    </Button>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {error ? (
        <div className="rounded-md border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">{error}</div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Trust Score"
          value={snapshot?.trust.trust_score ?? '-'}
          hint="Live backend trust engine"
          accent="hsl(var(--primary))"
        />
        <MetricCard label="Risk Level" value={snapshot?.trust.risk_level || '-'} hint="Computed per request" />
        <MetricCard label="Session" value={snapshot?.session.state || '-'} hint={`Expires ${formatTime(snapshot?.session.expires_at)}`} />
        <MetricCard
          label="Device"
          value={currentDevice?.trust_tier || '-'}
          hint={currentDevice?.id ? shortId(currentDevice.id) : 'no device'}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        {quickActionsCard}

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" />
              Current Security State
            </CardTitle>
            <CardDescription>Live backend state for the current identity/session/device.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <TrustScore score={snapshot?.trust.trust_score ?? 0} />

            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-3 py-2">
                <span className="text-muted-foreground">User</span>
                <span>{snapshot?.profile.email || '-'}</span>
              </div>
              <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-3 py-2">
                <span className="text-muted-foreground">Role</span>
                <span>{(snapshot?.profile.roles || session?.roles || []).join(', ') || '-'}</span>
              </div>
              <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-3 py-2">
                <span className="text-muted-foreground">Risk</span>
                <RiskBadge risk={snapshot?.trust?.risk_level || '-'} />
              </div>
              <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-3 py-2">
                <span className="text-muted-foreground">Token</span>
                <span>{snapshot?.token?.active ? 'Active' : 'Inactive'}</span>
              </div>
              <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-3 py-2">
                <span className="text-muted-foreground">Last Activity</span>
                <span>{formatTime(snapshot?.session.last_activity_at)}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {actionResults.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Recent Security Impact</CardTitle>
            <CardDescription>Simple log of trust changes from actions you ran.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {actionResults.map((result) => (
              <div key={result.id} className="flex items-start justify-between gap-3 rounded-md border border-border bg-muted/20 px-3 py-2 text-sm">
                <div>
                  <div className="font-medium">{result.title}</div>
                  <div className="text-xs text-muted-foreground">{result.detail}</div>
                </div>
                <div className="text-right">
                  <div className={result.trustDelta >= 0 ? 'text-success' : 'text-danger'}>
                    {result.trustDelta >= 0 ? '+' : ''}
                    {result.trustDelta}
                  </div>
                  <div className="text-xs text-muted-foreground">{formatTime(result.at)}</div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

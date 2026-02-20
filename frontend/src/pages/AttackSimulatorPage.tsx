import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AlertTriangle, Play, ShieldX } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { MetricCard } from '@/components/shared/MetricCard';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import {
  runAuthenticationAttackScenario,
  runDeviceImpersonationScenario,
  runReplayAttackScenario,
  runSessionHijackScenario,
} from '@/services/attackService';
import type { AttackResult } from '@/types/lucentid';
import { formatTime } from '@/lib/utils';

function scenarioLabel(value: AttackResult['scenario']) {
  switch (value) {
    case 'session_hijack':
      return 'Session Hijack Attempt';
    case 'replay_attack':
      return 'Replay Attack';
    case 'device_impersonation':
      return 'Device Impersonation';
    case 'authentication_attack':
      return 'Authentication Burst';
    default:
      return value;
  }
}

const DEMO_SEQUENCE: AttackResult['scenario'][] = [
  'session_hijack',
  'replay_attack',
  'device_impersonation',
  'authentication_attack',
];

export function AttackSimulatorPage() {
  const { serviceConfig, session } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const autoRunDoneRef = useRef(false);

  const [results, setResults] = useState<AttackResult[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const operatorConfig = useMemo(
    () =>
      session
        ? {
            ...serviceConfig,
          }
        : null,
    [serviceConfig, session]
  );

  const runScenario = useCallback(
    async (name: AttackResult['scenario']) => {
      if (!serviceConfig.baseUrl || !session?.tenantId) {
        setError('Missing backend base URL or tenant context.');
        return;
      }

      if (!session.signatureSecret) {
        setError('Request signature secret is required for signed attack flows.');
        return;
      }

      setError(null);
      setRunning(name);

      try {
        let result: AttackResult;
        if (name === 'session_hijack') {
          result = await runSessionHijackScenario(serviceConfig.baseUrl, session.tenantId, operatorConfig);
        } else if (name === 'replay_attack') {
          result = await runReplayAttackScenario(
            serviceConfig.baseUrl,
            session.tenantId,
            operatorConfig,
            session.signatureSecret
          );
        } else if (name === 'device_impersonation') {
          result = await runDeviceImpersonationScenario(serviceConfig.baseUrl, session.tenantId, operatorConfig);
        } else {
          result = await runAuthenticationAttackScenario(serviceConfig.baseUrl, session.tenantId, operatorConfig);
        }

        setResults((prev) => [result, ...prev].slice(0, 30));
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Scenario failed');
      } finally {
        setRunning(null);
      }
    },
    [operatorConfig, serviceConfig.baseUrl, session]
  );

  const runDemo = useCallback(async () => {
    for (const scenario of DEMO_SEQUENCE) {
      // eslint-disable-next-line no-await-in-loop
      await runScenario(scenario);
    }
  }, [runScenario]);

  useEffect(() => {
    if (searchParams.get('autorun') !== '1') {
      return;
    }
    if (autoRunDoneRef.current || running) {
      return;
    }
    autoRunDoneRef.current = true;
    runDemo();
  }, [runDemo, running, searchParams]);

  const summary = useMemo(() => {
    const total = results.length;
    const blocked = results.filter((item) => item.blocked).length;
    const alerts = results.filter((item) => item.alert_triggered).length;

    const trustChanges = results
      .map((item) => {
        if (typeof item.trust_before !== 'number' || typeof item.trust_after !== 'number') {
          return null;
        }
        return item.trust_after - item.trust_before;
      })
      .filter((value): value is number => value !== null);

    const avgTrustDelta = trustChanges.length
      ? Math.round((trustChanges.reduce((sum, value) => sum + value, 0) / trustChanges.length) * 10) / 10
      : 0;

    return {
      total,
      blocked,
      alerts,
      avgTrustDelta,
    };
  }, [results]);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-warning" />
            Demo Flow
          </CardTitle>
          <CardDescription>Run the 4 attack sequence, then open SOC to show detections in real time.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
            <Button onClick={runDemo} disabled={!!running} className="justify-start">
              <Play className="mr-2 h-4 w-4" />
              Start Full Attack Demo
            </Button>
            <Button variant="outline" onClick={() => navigate('/soc')} className="justify-start">
              Open SOC Monitor
            </Button>
            <Button variant="outline" onClick={() => setResults([])} className="justify-start" disabled={!!running}>
              Clear Results
            </Button>
            <Button variant="outline" onClick={() => navigate('/dashboard')} className="justify-start">
              Back to Dashboard
            </Button>
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <Button
              variant="outline"
              onClick={() => runScenario('session_hijack')}
              disabled={!!running}
              className="justify-start"
            >
              Session Hijack
            </Button>
            <Button
              variant="outline"
              onClick={() => runScenario('replay_attack')}
              disabled={!!running}
              className="justify-start"
            >
              Replay Attack
            </Button>
            <Button
              variant="outline"
              onClick={() => runScenario('device_impersonation')}
              disabled={!!running}
              className="justify-start"
            >
              Device Impersonation
            </Button>
            <Button
              variant="outline"
              onClick={() => runScenario('authentication_attack')}
              disabled={!!running}
              className="justify-start"
            >
              Authentication Burst
            </Button>
          </div>

          {running ? (
            <div className="rounded-md border border-primary/30 bg-primary/10 px-3 py-2 text-sm text-primary">
              Running scenario: {scenarioLabel(running as AttackResult['scenario'])}
            </div>
          ) : null}

          {error ? (
            <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</div>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Scenarios Run" value={summary.total} hint="Results in current table" />
        <MetricCard label="Blocked" value={summary.blocked} hint="Attacks denied by backend" />
        <MetricCard label="Alerts Triggered" value={summary.alerts} hint="Risk or anomaly detections" />
        <MetricCard
          label="Avg Trust Delta"
          value={`${summary.avgTrustDelta >= 0 ? '+' : ''}${summary.avgTrustDelta}`}
          hint="From scenarios with trust before/after"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldX className="h-4 w-4 text-primary" />
            Detection Results
          </CardTitle>
          <CardDescription>Real responses, trust impact, session outcomes, and alert status.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scenario</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Decision</TableHead>
                  <TableHead>Trust Before</TableHead>
                  <TableHead>Trust After</TableHead>
                  <TableHead>Session</TableHead>
                  <TableHead>Alert</TableHead>
                  <TableHead>Detail</TableHead>
                  <TableHead>Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-muted-foreground">
                      Run the full demo or a single scenario to generate results.
                    </TableCell>
                  </TableRow>
                ) : (
                  results.map((result, index) => (
                    <TableRow key={`${result.scenario}-${index}-${result.recorded_at}`}>
                      <TableCell>{scenarioLabel(result.scenario)}</TableCell>
                      <TableCell>{result.status_code}</TableCell>
                      <TableCell>
                        <Badge variant={result.blocked ? 'success' : 'danger'}>
                          {result.blocked ? 'Blocked' : 'Allowed'}
                        </Badge>
                      </TableCell>
                      <TableCell>{result.trust_before ?? '-'}</TableCell>
                      <TableCell>{result.trust_after ?? '-'}</TableCell>
                      <TableCell>{result.session_state_after || '-'}</TableCell>
                      <TableCell>
                        <Badge variant={result.alert_triggered ? 'danger' : 'outline'}>
                          {result.alert_triggered ? 'Triggered' : 'None'}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[260px] truncate">{result.detail}</TableCell>
                      <TableCell>{formatTime(result.recorded_at)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

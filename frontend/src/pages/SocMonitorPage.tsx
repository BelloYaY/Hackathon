import { useCallback, useMemo, useState } from 'react';
import { AlertTriangle, BellRing, Radar, Shield } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { MetricCard } from '@/components/shared/MetricCard';
import { RiskBadge } from '@/components/shared/RiskBadge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { usePolling } from '@/hooks/usePolling';
import { useRealtimeTransport } from '@/hooks/useRealtimeTransport';
import { useAuth } from '@/hooks/useAuth';
import {
  getAuditEvents,
  getAuditIntegrity,
  getBehaviorEvents,
  getRiskEvents,
  getSecurityOverview,
  getSessions,
} from '@/services/lucentidService';
import { ApiError } from '@/services/apiClient';
import { formatTime, shortId } from '@/lib/utils';
import type { AuditEvent, BehaviorEvent, RiskEvent, SecurityOverview, TenantSession } from '@/types/lucentid';

interface SocState {
  overview: SecurityOverview | null;
  riskEvents: RiskEvent[];
  behaviorEvents: BehaviorEvent[];
  auditEvents: AuditEvent[];
  sessions: TenantSession[];
  integrity: { valid: boolean; details: string } | null;
}

export function SocMonitorPage() {
  const { serviceConfig } = useAuth();
  const realtime = useRealtimeTransport(serviceConfig.baseUrl);

  const [data, setData] = useState<SocState>({
    overview: null,
    riskEvents: [],
    behaviorEvents: [],
    auditEvents: [],
    sessions: [],
    integrity: null,
  });
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [overview, riskEvents, behaviorEvents, auditEvents, integrity, sessions] = await Promise.all([
        getSecurityOverview(serviceConfig),
        getRiskEvents(serviceConfig, 60),
        getBehaviorEvents(serviceConfig, 60),
        getAuditEvents(serviceConfig, 120),
        getAuditIntegrity(serviceConfig),
        getSessions(serviceConfig, 100),
      ]);

      setData({
        overview,
        riskEvents,
        behaviorEvents,
        auditEvents,
        integrity,
        sessions,
      });
      setError(null);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed loading SOC feeds');
      }
    }
  }, [serviceConfig]);

  usePolling(load, realtime.mode === 'socket' ? 5500 : 3200, !!serviceConfig.accessToken);

  const severityDistribution = useMemo(() => {
    const severityMap = new Map<string, number>();
    for (const event of data.riskEvents) {
      severityMap.set(event.severity, (severityMap.get(event.severity) || 0) + 1);
    }

    return ['critical', 'high', 'elevated', 'guarded', 'low'].map((severity) => ({
      severity,
      count: severityMap.get(severity) || 0,
    }));
  }, [data.riskEvents]);

  const trustTrend = useMemo(() => {
    return data.auditEvents
      .filter((event) => event.event_type === 'enforcement' && typeof event.metadata?.trustScore === 'number')
      .slice(0, 30)
      .reverse()
      .map((event, index) => ({
        index: index + 1,
        trust: Number(event.metadata.trustScore),
      }));
  }, [data.auditEvents]);

  const liveAlerts = useMemo(() => {
    const riskAlerts = data.riskEvents
      .filter((event) => event.severity === 'high' || event.severity === 'critical')
      .map((event) => ({
        id: event.id,
        type: 'risk',
        message: `${event.event_type} (${event.severity})`,
        createdAt: event.created_at,
      }));

    const behaviorAlerts = data.behaviorEvents
      .filter((event) => event.anomaly_score >= 70)
      .map((event) => ({
        id: event.id,
        type: 'behavior',
        message: `${event.event_type} (anomaly ${event.anomaly_score})`,
        createdAt: event.created_at,
      }));

    return [...riskAlerts, ...behaviorAlerts]
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 40);
  }, [data.behaviorEvents, data.riskEvents]);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>SOC Demo View</CardTitle>
          <CardDescription>Use this page after running the attack simulator to show live detections.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="rounded-md border border-border bg-muted/20 p-3">
            1. Run full attack demo first. 2. Open this page. 3. Show alerts, sessions, and audit updates.
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={load}>
              Refresh Now
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Active Sessions" value={data.overview?.active_sessions ?? '-'} hint="state active/elevated/locked" />
        <MetricCard label="High Risk 24h" value={data.overview?.high_risk_events_24h ?? '-'} hint="risk events" />
        <MetricCard label="Anomalies 24h" value={data.overview?.high_anomaly_events_24h ?? '-'} hint="behavior anomalies" />
        <MetricCard label="Revoked Tokens" value={data.overview?.revoked_tokens_total ?? '-'} hint="tenant total" />
        <MetricCard
          label="Audit Integrity"
          value={data.integrity?.valid ? 'valid' : 'invalid'}
          hint={data.integrity?.details || 'pending'}
          accent={data.integrity?.valid ? 'hsl(var(--success))' : undefined}
        />
        <MetricCard
          label="Live Transport"
          value={realtime.mode}
          hint={realtime.connected ? 'socket active' : 'polling mode'}
        />
      </div>

      {error ? (
        <div className="rounded-md border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">{error}</div>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radar className="h-4 w-4 text-primary" />
              Risk Severity Distribution
            </CardTitle>
            <CardDescription>From `/monitor/risk-events`.</CardDescription>
          </CardHeader>
          <CardContent className="h-[260px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityDistribution}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(86,101,122,0.2)" />
                <XAxis dataKey="severity" stroke="rgba(180,200,220,0.6)" />
                <YAxis stroke="rgba(180,200,220,0.6)" />
                <Tooltip
                  contentStyle={{
                    borderRadius: 8,
                    border: '1px solid rgba(100,120,160,0.35)',
                    background: 'rgba(10,14,24,0.95)',
                  }}
                />
                <Bar dataKey="count" fill="hsl(var(--primary))" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Trust Drift Timeline
            </CardTitle>
            <CardDescription>Derived from enforcement audit metadata.</CardDescription>
          </CardHeader>
          <CardContent className="h-[260px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trustTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(86,101,122,0.2)" />
                <XAxis dataKey="index" stroke="rgba(180,200,220,0.6)" />
                <YAxis domain={[0, 100]} stroke="rgba(180,200,220,0.6)" />
                <Tooltip
                  contentStyle={{
                    borderRadius: 8,
                    border: '1px solid rgba(100,120,160,0.35)',
                    background: 'rgba(10,14,24,0.95)',
                  }}
                />
                <Line type="monotone" dataKey="trust" stroke="hsl(var(--success))" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.1fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BellRing className="h-4 w-4 text-warning" />
              Live Security Alerts
            </CardTitle>
            <CardDescription>Risk and anomaly detections from monitoring feeds.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="max-h-[360px] overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Message</TableHead>
                    <TableHead>Timestamp</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {liveAlerts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={3} className="text-center text-muted-foreground">
                        No alerts in current feed.
                      </TableCell>
                    </TableRow>
                  ) : (
                    liveAlerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell>
                          <Badge variant={alert.type === 'risk' ? 'danger' : 'warning'}>{alert.type}</Badge>
                        </TableCell>
                        <TableCell>{alert.message}</TableCell>
                        <TableCell>{formatTime(alert.createdAt)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-primary" />
              Session Events
            </CardTitle>
            <CardDescription>From `/session` admin endpoint.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="max-h-[360px] overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Session</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Risk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.sessions.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-muted-foreground">
                        No active tenant sessions visible.
                      </TableCell>
                    </TableRow>
                  ) : (
                    data.sessions.slice(0, 40).map((session) => (
                      <TableRow key={session.id}>
                        <TableCell className="font-mono text-xs">{shortId(session.id)}</TableCell>
                        <TableCell className="max-w-[140px] truncate">{session.user_email}</TableCell>
                        <TableCell>{session.state}</TableCell>
                        <TableCell>
                          <RiskBadge risk={session.risk_level} />
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Audit Log Stream</CardTitle>
          <CardDescription>Real audit trail from `/audit/events` with integrity chain context.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="max-h-[320px] overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Event</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Decision</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.auditEvents.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                      No audit events available.
                    </TableCell>
                  </TableRow>
                ) : (
                  data.auditEvents.slice(0, 80).map((event) => (
                    <TableRow key={event.id}>
                      <TableCell>{event.event_type}</TableCell>
                      <TableCell>{event.action_name}</TableCell>
                      <TableCell>
                        <Badge variant={event.decision === 'deny' ? 'danger' : event.decision === 'allow' ? 'success' : 'outline'}>
                          {event.decision}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[220px] truncate">{event.target_id}</TableCell>
                      <TableCell>{formatTime(event.created_at)}</TableCell>
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

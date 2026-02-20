import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Loader2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { useAuth } from '@/hooks/useAuth';
import { ApiError } from '@/services/apiClient';
import { bootstrapTenant, registerUser } from '@/services/lucentidService';

export function LoginPage() {
  const {
    login,
    backendBaseUrl,
    discoveryState,
    discoveryError,
  } = useAuth();
  const navigate = useNavigate();

  const [baseUrl, setBaseUrl] = useState(backendBaseUrl || '/api/v1');
  const [tenantId, setTenantId] = useState('tenant-a');
  const [email, setEmail] = useState('admin@monitor.com');
  const [password, setPassword] = useState('Str0ng!Password#1');
  const [deviceId, setDeviceId] = useState(`console-${Math.random().toString(36).slice(2, 10)}`);
  const [otpCode, setOtpCode] = useState('');
  const [signatureSecret, setSignatureSecret] = useState(
    import.meta.env.VITE_REQUEST_SIGNATURE_SECRET || 'lucentid-request-signature-secret'
  );
  const [bootstrapKey, setBootstrapKey] = useState(
    import.meta.env.VITE_BOOTSTRAP_KEY || 'lucentid-bootstrap-admin'
  );
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isBootstrapping, setIsBootstrapping] = useState(false);

  useEffect(() => {
    if (backendBaseUrl) {
      setBaseUrl(backendBaseUrl);
    }
  }, [backendBaseUrl]);

  const discoveryBadge = useMemo(() => {
    if (discoveryState === 'ready') {
      return <Badge variant="success">Backend detected</Badge>;
    }
    if (discoveryState === 'error') {
      return <Badge variant="danger">Discovery failed</Badge>;
    }
    return <Badge variant="warning">Detecting backend...</Badge>;
  }, [discoveryState]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    setIsSubmitting(true);

    try {
      await login({
        baseUrl,
        tenantId,
        email,
        password,
        deviceId,
        otpCode: otpCode || undefined,
        signatureSecret,
      });
      navigate('/dashboard', { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Login failed');
      }
    } finally {
      setIsSubmitting(false);
    }
  }

  async function bootstrapAndCreateDemoAccount(role: 'admin' | 'user') {
    setError(null);
    setNotice(null);
    setIsBootstrapping(true);

    const resolvedBaseUrl = baseUrl || '/api/v1';
    const resolvedTenantId = tenantId.trim() || 'tenant-a';
    const tenantName = resolvedTenantId
      .split('-')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ');

    try {
      try {
        await bootstrapTenant(resolvedBaseUrl, {
          bootstrapKey,
          tenantId: resolvedTenantId,
          name: tenantName,
        });
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 409) {
          throw err;
        }
      }

      let createdEmail = role === 'admin' ? 'admin@corp.com' : 'user@corp.com';

      try {
        await registerUser(resolvedBaseUrl, {
          tenantId: resolvedTenantId,
          email: createdEmail,
          password,
          roles: [role],
        });
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) {
          createdEmail = `${role}.${Date.now()}@corp.com`;
          await registerUser(resolvedBaseUrl, {
            tenantId: resolvedTenantId,
            email: createdEmail,
            password,
            roles: [role],
          });
        } else {
          throw err;
        }
      }

      setTenantId(resolvedTenantId);
      setEmail(createdEmail);
      setNotice(`${role === 'admin' ? 'Admin' : 'User'} demo account ready: ${createdEmail} (${resolvedTenantId})`);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError(`Unable to bootstrap tenant/${role} account`);
      }
    } finally {
      setIsBootstrapping(false);
    }
  }

  async function handleBootstrapAndCreateAdmin() {
    await bootstrapAndCreateDemoAccount('admin');
  }

  async function handleBootstrapAndCreateUser() {
    await bootstrapAndCreateDemoAccount('user');
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-8">
      <Card className="w-full max-w-xl">
        <CardHeader>
          <div className="mb-3 inline-flex w-fit items-center gap-2 rounded-md bg-primary/20 px-3 py-1 text-primary">
            <ShieldCheck className="h-4 w-4" />
            LucentID Core
          </div>
          <CardTitle className="text-2xl">Live Security Console Login</CardTitle>
          <CardDescription>
            Authenticate against the real backend to access user, simulator, and SOC interfaces.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={handleSubmit}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              {discoveryBadge}
              {discoveryError ? <span className="text-xs text-danger">{discoveryError}</span> : null}
            </div>

            <div className="space-y-2">
              <Label htmlFor="base-url">Backend Base URL</Label>
              <Input
                id="base-url"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="/api/v1"
                required
              />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="tenant-id">Tenant ID</Label>
                <Input id="tenant-id" value={tenantId} onChange={(e) => setTenantId(e.target.value)} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-id">Device ID</Label>
                <Input id="device-id" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} required />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type="password"
                required
              />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="otp">OTP (optional)</Label>
                <Input id="otp" value={otpCode} onChange={(e) => setOtpCode(e.target.value)} placeholder="123456" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="signature-secret">Request Signature Secret</Label>
                <Input
                  id="signature-secret"
                  value={signatureSecret}
                  onChange={(e) => setSignatureSecret(e.target.value)}
                  placeholder="Needed for signed endpoints"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="bootstrap-key">Bootstrap Key (for first-time setup)</Label>
              <Input
                id="bootstrap-key"
                value={bootstrapKey}
                onChange={(e) => setBootstrapKey(e.target.value)}
                placeholder="lucentid-bootstrap-admin"
              />
            </div>

            {error ? <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</div> : null}
            {notice ? <div className="rounded-md border border-success/40 bg-success/10 px-3 py-2 text-sm text-success">{notice}</div> : null}

            <div className="grid gap-3 sm:grid-cols-2">
              <Button type="button" variant="secondary" className="w-full" disabled={isBootstrapping} onClick={handleBootstrapAndCreateUser}>
                {isBootstrapping ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Create User Demo
              </Button>
              <Button type="button" variant="secondary" className="w-full" disabled={isBootstrapping} onClick={handleBootstrapAndCreateAdmin}>
                {isBootstrapping ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Create Admin Demo
              </Button>
            </div>

            <Button className="w-full" type="submit" disabled={isSubmitting}>
              {isSubmitting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Sign in to LucentID
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

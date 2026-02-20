import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import { discoverBackendBaseUrl, normalizeBaseUrl } from '@/services/backendDiscovery';
import { login as loginRequest } from '@/services/lucentidService';
import { ApiError } from '@/services/apiClient';
import type { ServiceConfig } from '@/services/apiClient';

const STORAGE_KEY = 'lucentid-console-session';

interface AuthSession {
  tenantId: string;
  deviceId: string;
  email: string;
  userId: string;
  roles: string[];
  accessToken: string;
  refreshToken: string;
  signatureSecret: string;
}

interface LoginValues {
  baseUrl?: string;
  tenantId: string;
  email: string;
  password: string;
  deviceId: string;
  otpCode?: string;
  signatureSecret: string;
}

interface AuthContextValue {
  session: AuthSession | null;
  isAuthenticated: boolean;
  backendBaseUrl: string;
  discoveryState: 'detecting' | 'ready' | 'error';
  discoveryError: string | null;
  setBackendBaseUrl: (baseUrl: string) => void;
  login: (values: LoginValues) => Promise<void>;
  logout: () => void;
  updateTokens: (tokens: { accessToken: string; refreshToken: string }) => void;
  setSignatureSecret: (secret: string) => void;
  serviceConfig: ServiceConfig;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

function loadInitialState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return { session: null as AuthSession | null, baseUrl: '' };
    }
    const parsed = JSON.parse(raw) as { session: AuthSession | null; baseUrl: string };
    return {
      session: parsed.session,
      baseUrl: parsed.baseUrl || '',
    };
  } catch {
    return { session: null as AuthSession | null, baseUrl: '' };
  }
}

function persistState(session: AuthSession | null, baseUrl: string) {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      session,
      baseUrl,
    })
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const initial = useMemo(loadInitialState, []);
  const [session, setSession] = useState<AuthSession | null>(initial.session);
  const [backendBaseUrl, setBackendBaseUrlState] = useState<string>(initial.baseUrl || '');
  const [discoveryState, setDiscoveryState] = useState<'detecting' | 'ready' | 'error'>(
    initial.baseUrl ? 'ready' : 'detecting'
  );
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);

  useEffect(() => {
    persistState(session, backendBaseUrl);
  }, [session, backendBaseUrl]);

  useEffect(() => {
    document.documentElement.classList.add('dark');
  }, []);

  useEffect(() => {
    if (backendBaseUrl) {
      setDiscoveryState('ready');
      setDiscoveryError(null);
      return;
    }

    let cancelled = false;
    setDiscoveryState('detecting');

    discoverBackendBaseUrl()
      .then((url) => {
        if (cancelled) return;
        setBackendBaseUrlState(url);
        setDiscoveryState('ready');
        setDiscoveryError(null);
      })
      .catch((error: Error) => {
        if (cancelled) return;
        setDiscoveryState('error');
        setDiscoveryError(error.message);
      });

    return () => {
      cancelled = true;
    };
  }, [backendBaseUrl]);

  const setBackendBaseUrl = useCallback((url: string) => {
    const normalized = normalizeBaseUrl(url);
    setBackendBaseUrlState(normalized);
    setDiscoveryState('ready');
    setDiscoveryError(null);
  }, []);

  const updateTokens = useCallback((tokens: { accessToken: string; refreshToken: string }) => {
    setSession((prev) => {
      if (!prev) {
        return prev;
      }
      return {
        ...prev,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    });
  }, []);

  const setSignatureSecret = useCallback((secret: string) => {
    setSession((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        signatureSecret: secret,
      };
    });
  }, []);

  const login = useCallback(
    async (values: LoginValues) => {
      const targetBaseUrl = normalizeBaseUrl(values.baseUrl || backendBaseUrl);
      if (!targetBaseUrl) {
        throw new Error('Backend base URL is required');
      }

      let activeBaseUrl = targetBaseUrl;
      if (activeBaseUrl !== backendBaseUrl) {
        setBackendBaseUrlState(activeBaseUrl);
        setDiscoveryState('ready');
      }

      let response;
      try {
        response = await loginRequest(activeBaseUrl, {
          tenantId: values.tenantId,
          email: values.email,
          password: values.password,
          deviceId: values.deviceId,
          otpCode: values.otpCode,
        });
      } catch (error) {
        const isLikelyRouteMiss =
          error instanceof ApiError &&
          error.status === 404 &&
          (activeBaseUrl.startsWith('/') || !activeBaseUrl.startsWith('http'));

        if (!isLikelyRouteMiss) {
          throw error;
        }

        const discoveredBaseUrl = normalizeBaseUrl(await discoverBackendBaseUrl());
        if (!discoveredBaseUrl || discoveredBaseUrl === activeBaseUrl) {
          throw error;
        }

        activeBaseUrl = discoveredBaseUrl;
        setBackendBaseUrlState(activeBaseUrl);
        setDiscoveryState('ready');
        setDiscoveryError(null);

        response = await loginRequest(activeBaseUrl, {
          tenantId: values.tenantId,
          email: values.email,
          password: values.password,
          deviceId: values.deviceId,
          otpCode: values.otpCode,
        });
      }

      setSession({
        tenantId: values.tenantId,
        deviceId: values.deviceId,
        email: response.user.email,
        userId: response.user.id,
        roles: response.user.roles,
        accessToken: response.access_token,
        refreshToken: response.refresh_token,
        signatureSecret: values.signatureSecret,
      });
    },
    [backendBaseUrl]
  );

  const logout = useCallback(() => {
    setSession(null);
  }, []);

  const serviceConfig = useMemo<ServiceConfig>(
    () => ({
      baseUrl: backendBaseUrl,
      tenantId: session?.tenantId,
      deviceId: session?.deviceId,
      accessToken: session?.accessToken,
      refreshToken: session?.refreshToken,
      signatureSecret: session?.signatureSecret,
      onTokens: updateTokens,
      onAuthFailure: logout,
    }),
    [backendBaseUrl, logout, session, updateTokens]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      isAuthenticated: !!session?.accessToken,
      backendBaseUrl,
      discoveryState,
      discoveryError,
      setBackendBaseUrl,
      login,
      logout,
      updateTokens,
      setSignatureSecret,
      serviceConfig,
    }),
    [
      session,
      backendBaseUrl,
      discoveryState,
      discoveryError,
      setBackendBaseUrl,
      login,
      logout,
      updateTokens,
      setSignatureSecret,
      serviceConfig,
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

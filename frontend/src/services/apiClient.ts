import { createSignedHeaders } from '@/lib/signature';

export class ApiError extends Error {
  status: number;
  payload: unknown;

  constructor(status: number, message: string, payload?: unknown) {
    super(message);
    this.status = status;
    this.payload = payload;
  }
}

export interface ServiceConfig {
  baseUrl: string;
  tenantId?: string;
  deviceId?: string;
  accessToken?: string;
  refreshToken?: string;
  signatureSecret?: string;
  onTokens?: (tokens: { accessToken: string; refreshToken: string }) => void;
  onAuthFailure?: () => void;
}

interface RequestOptions<TBody = unknown> {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: TBody;
  headers?: Record<string, string>;
  auth?: boolean;
  tenantId?: string;
  deviceId?: string;
  signed?: boolean;
  signatureSecret?: string;
  retryAuth?: boolean;
}

interface RefreshTokensResponse {
  access_token: string;
  refresh_token: string;
}

function withPath(baseUrl: string, path: string) {
  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }
  return `${baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
}

async function parseResponse(res: Response) {
  const contentType = res.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return null;
  }
  return res.json();
}

async function refreshTokens(config: ServiceConfig) {
  if (!config.refreshToken || !config.deviceId || !config.tenantId) {
    return null;
  }

  const res = await fetch(withPath(config.baseUrl, '/token/refresh'), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-tenant-id': config.tenantId,
    },
    body: JSON.stringify({
      refresh_token: config.refreshToken,
      device_id: config.deviceId,
    }),
  });

  if (!res.ok) {
    return null;
  }

  const data = (await parseResponse(res)) as RefreshTokensResponse | null;
  if (!data?.access_token || !data.refresh_token) {
    return null;
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
  };
}

export async function apiRequest<TResponse, TBody = unknown>(
  config: ServiceConfig,
  path: string,
  options: RequestOptions<TBody> = {}
): Promise<TResponse> {
  const method = options.method ?? 'GET';
  const auth = options.auth ?? true;
  const retryAuth = options.retryAuth ?? true;
  const tenantId = options.tenantId ?? config.tenantId;
  const deviceId = options.deviceId ?? config.deviceId;
  const body = options.body;

  if (!config.baseUrl) {
    throw new ApiError(500, 'Backend base URL is not configured');
  }

  const baseHeaders: Record<string, string> = {
    accept: 'application/json',
    ...(options.headers || {}),
  };

  if (tenantId) {
    baseHeaders['x-tenant-id'] = tenantId;
  }

  if (auth) {
    if (!config.accessToken) {
      throw new ApiError(401, 'Missing access token');
    }
    if (!deviceId) {
      throw new ApiError(400, 'Missing device ID');
    }
    baseHeaders.authorization = `Bearer ${config.accessToken}`;
    baseHeaders['x-device-id'] = deviceId;
  }

  if (body !== undefined && !baseHeaders['content-type']) {
    baseHeaders['content-type'] = 'application/json';
  }

  if (options.signed) {
    const secret = options.signatureSecret ?? config.signatureSecret;
    if (!secret) {
      throw new ApiError(400, 'Missing request signature secret');
    }
    const signed = await createSignedHeaders(secret, body ?? {});
    Object.assign(baseHeaders, signed);
  }

  const makeRequest = async (token?: string) => {
    const requestHeaders: Record<string, string> = { ...baseHeaders };
    if (auth && token) {
      requestHeaders.authorization = `Bearer ${token}`;
    }

    return fetch(withPath(config.baseUrl, path), {
      method,
      headers: requestHeaders,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  };

  let res = await makeRequest(config.accessToken);

  if (res.status === 401 && auth && retryAuth) {
    const refreshed = await refreshTokens(config);
    if (refreshed) {
      config.onTokens?.(refreshed);
      res = await makeRequest(refreshed.accessToken);
    } else {
      config.onAuthFailure?.();
    }
  }

  const payload = await parseResponse(res);

  if (!res.ok) {
    const message =
      (payload && typeof payload === 'object' && 'detail' in payload && String((payload as { detail: string }).detail)) ||
      res.statusText ||
      'Request failed';
    throw new ApiError(res.status, message, payload);
  }

  return payload as TResponse;
}

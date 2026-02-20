import { useEffect, useMemo, useState } from 'react';
import { io } from 'socket.io-client';

interface RealtimeState {
  mode: 'socket' | 'polling';
  connected: boolean;
}

function toOrigin(baseUrl: string) {
  if (!baseUrl) {
    return window.location.origin;
  }
  if (baseUrl.startsWith('http://') || baseUrl.startsWith('https://')) {
    return new URL(baseUrl).origin;
  }
  return window.location.origin;
}

export function useRealtimeTransport(baseUrl: string) {
  const [state, setState] = useState<RealtimeState>({
    mode: 'polling',
    connected: false,
  });

  const origin = useMemo(() => toOrigin(baseUrl), [baseUrl]);

  useEffect(() => {
    if (!origin) {
      return;
    }

    let settled = false;
    const socket = io(origin, {
      path: '/socket.io',
      transports: ['websocket'],
      reconnection: false,
      timeout: 1200,
      autoConnect: true,
    });

    const setPolling = () => {
      if (settled) return;
      settled = true;
      setState({ mode: 'polling', connected: false });
      socket.close();
    };

    const setSocket = () => {
      if (settled) return;
      settled = true;
      setState({ mode: 'socket', connected: true });
    };

    socket.on('connect', setSocket);
    socket.on('connect_error', setPolling);

    const fallbackTimer = window.setTimeout(setPolling, 1800);

    return () => {
      window.clearTimeout(fallbackTimer);
      socket.close();
    };
  }, [origin]);

  return state;
}

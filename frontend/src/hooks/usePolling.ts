import { useEffect, useRef } from 'react';

export function usePolling(callback: () => Promise<void> | void, intervalMs: number, enabled = true) {
  const callbackRef = useRef(callback);

  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let running = false;

    const tick = async () => {
      if (running) return;
      running = true;
      try {
        await callbackRef.current();
      } finally {
        running = false;
      }
    };

    void tick();
    const id = window.setInterval(() => {
      void tick();
    }, intervalMs);

    return () => {
      window.clearInterval(id);
    };
  }, [enabled, intervalMs]);
}

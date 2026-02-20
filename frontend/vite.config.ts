import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

const backendTarget = process.env.VITE_BACKEND_TARGET;

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: backendTarget
    ? {
        proxy: {
          '/api': {
            target: backendTarget,
            changeOrigin: true,
          },
        },
      }
    : undefined,
});

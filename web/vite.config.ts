/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Same-origin in production: the SPA and the API sit behind one CloudFront origin, so the client
// uses relative paths and there is no CORS. In dev, Vite proxies the API paths to the local Go api.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/memories': 'http://localhost:8080',
      '/erase': 'http://localhost:8080',
      '/healthz': 'http://localhost:8080',
    },
  },
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // e2e/ holds Playwright specs (their own runner); keep vitest to the unit tests under src/.
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    exclude: ['e2e/**', 'node_modules/**'],
  },
})

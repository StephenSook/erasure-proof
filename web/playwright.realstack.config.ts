import { defineConfig, devices } from '@playwright/test'

// Real-stack E2E: the browser drives the whole loop against a LIVE backend with ZERO mocks. The
// CI job (e2e-realstack) starts CockroachDB, moto-server (KMS + S3 Object Lock), cryptod, and the
// Go api first; this config then starts the vite dev server (no VITE_USE_MOCK, so getClient()
// returns the real HTTP client) whose proxy forwards /api, /erase, /memories to the Go api on
// :8080. So a green run proves ingest, C-SPANN search, AS OF SYSTEM TIME, the SERIALIZABLE erasure,
// real KMS envelope + key destruction, ECDSA sign + S3 Object Lock anchor, browser proof
// verification, and the 42501 RBAC denial all run wired together over real HTTP + SQL + crypto.

const PORT = 5173

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/realstack.spec.ts',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // Non-mock build: the dev server's proxy (vite.config.ts) forwards to the Go api on :8080.
    command: 'npm run dev',
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})

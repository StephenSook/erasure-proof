import { defineConfig, devices } from '@playwright/test'

// End-to-end tests that drive the REAL browser through the whole erasure loop in mock mode
// (VITE_USE_MOCK=1), so every push proves the console still runs request-to-proof unaided. The
// mock mirrors the cloud behaviour (real WebCrypto proof verification, 42501 RBAC denial, live
// timeline), so this catches UI/console regressions without a backend. A real-stack variant against
// the deployed URL is a separate, post-deploy job.

const PORT = 4173

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // VITE_USE_MOCK is a build-time flag, so it must be set for the BUILD, then serve that bundle
    // (the production bundle in mock mode, closest to what judges load).
    command: `VITE_USE_MOCK=1 npm run build && npm run preview`,
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})

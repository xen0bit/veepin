import { defineConfig } from '@playwright/test';

// The management plane under test. CI passes PANEL_HARNESS pointing at a binary
// built once (go build ./tests/e2e/harness); locally the config falls back to
// `go run`, which compiles on demand. The remaining variables are shared
// between the webServer command and the specs (see lib/config.ts), so they stay
// in one place.
const HARNESS = process.env.PANEL_HARNESS ?? 'go run ./harness';
const ADDR = process.env.PANEL_ADDR ?? '127.0.0.1:18555';
const TOKEN = process.env.PANEL_TOKEN ?? 'veepin-e2e-token';

export default defineConfig({
  testDir: './tests',
  // The harness is one mutable world shared by every test. Serial, one worker:
  // tests create only uniquely-named entities and clean up after themselves, and
  // that discipline is only sound when nothing runs concurrently.
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://${ADDR}`,
    browserName: 'chromium',
    headless: true,
    acceptDownloads: true,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `${HARNESS} -addr ${ADDR} -token ${TOKEN} -seed ./fixtures/seed.json`,
    // The panel root, not /api/health: the API answers 401 without the bearer
    // token, and this wait is just a liveness probe.
    url: `http://${ADDR}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    cwd: __dirname,
  },
});

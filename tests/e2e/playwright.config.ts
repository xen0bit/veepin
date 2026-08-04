import { execFileSync } from 'node:child_process';
import { defineConfig } from '@playwright/test';
import { TOKEN } from './lib/config';

// The management plane under test. CI passes PANEL_HARNESS pointing at a binary
// built once (go build ./tests/e2e/harness); locally the config falls back to
// `go run`, which compiles on demand. The bearer token is shared with the specs
// through lib/config.ts so it is written down once.
const HARNESS = process.env.PANEL_HARNESS ?? 'go run ./harness';

// freePort asks the kernel for an unused loopback port. The probe runs in a
// child process because the only port-allocation API Node offers is
// asynchronous, and this value is needed synchronously: Playwright reads
// webServer.url and use.baseURL at config load, before any hook could set them.
//
// The port was a hardcoded 18555. Two worktrees running `make e2e`, or two jobs
// on one self-hosted runner, then collided -- and with reuseExistingServer on,
// the second run silently drove the first run's harness and its half-mutated
// world, which is the failure nobody debugs because both runs look green until
// they do not.
//
// Between the probe closing its socket and the harness binding, another process
// could take the port. That window is milliseconds against a fixed port's
// permanent overlap, and losing it is a loud bind failure rather than a silent
// crossed wire.
function freePort(): number {
  const probe =
    "const s = require('net').createServer();" +
    "s.listen(0, '127.0.0.1', () => { process.stdout.write(String(s.address().port)); s.close(); });";
  const out = execFileSync(process.execPath, ['-e', probe], { encoding: 'utf8' });
  const port = Number(out.trim());
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error(`no free port for the harness (probe printed ${JSON.stringify(out)})`);
  }
  return port;
}

// Picked once and pinned into the environment. Playwright re-loads this file in
// every worker process to read `use`, and each worker inherits process.env from
// the main process at fork time -- so writing the choice back is what makes all
// of them agree. Without it each spec file probed for its own port and pointed
// Chromium at a port nothing was listening on, while the single harness the main
// process started sat on the first one.
const ADDR = process.env.PANEL_ADDR ?? `127.0.0.1:${freePort()}`;
process.env.PANEL_ADDR = ADDR;

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
    // Never reuse a running harness. It serves a world the tests mutate, so a
    // survivor from an earlier run answers with whatever that run left behind --
    // the same trap AGENTS.md documents for `docker compose` reusing a container
    // when only a bind-mounted file changed. A fresh process costs a second of
    // `go run` and is the difference between a real result and a plausible one.
    reuseExistingServer: false,
    timeout: 60_000,
    cwd: __dirname,
  },
});

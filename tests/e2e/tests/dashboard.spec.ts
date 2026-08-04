import type { APIRequestContext } from '@playwright/test';
import { expect, test } from '@playwright/test';
import { api } from '../lib/api';
import { uniqueName } from '../lib/unique';

// The dashboard: fleet table with filter, expandable detail (redacted config +
// peers), the audit trail, and the log tail. The harness serves one mutable
// world, so assertions target the seeded names and the entities each test
// created, never exact fleet-wide counts -- a test that failed mid-cleanup must
// not cascade a false failure into the next one.

const SEED_PEER = 'e2e-peer-AAAABBBBCCCCDDDDEEEEFFFF000011112222333344445555';
const SEED_SECRET = '811WYV9bqgEduWyGDs+V+xJyo7Gx6Zo4Qn+HoB8Y6rk=';
// The `peers` option exactly as fixtures/seed.json writes it, so a test that
// removes the seeded peer can put the world back the way it found it.
const SEED_PEERS_OPTION = JSON.stringify([
  { 'public-key': SEED_PEER, 'allowed-ips': ['10.10.0.2/32'] },
]);

test.describe.configure({ mode: 'serial' });

test('the dashboard shows supervisor health and the seeded fleet', async ({ page }) => {
  await page.goto('/');

  // Health header rendered from /api/health.
  await expect(page.locator('#health')).toContainText('status: ok');

  // Each seeded listener renders its columns.
  const rows = page.locator('#listeners tbody tr:not(.detail-row)');
  await expect(rows.filter({ hasText: 'site-a' })).toContainText('wireguard');
  await expect(rows.filter({ hasText: 'site-a' })).toContainText('running');
  await expect(rows.filter({ hasText: 'site-a' })).toContainText('10.10.0.1');
  await expect(rows.filter({ hasText: 'broken' })).toContainText('toy');
  await expect(rows.filter({ hasText: 'broken' })).toContainText('error');
  await expect(rows.filter({ hasText: 'down' })).toContainText('stopped');
  await expect(rows.filter({ hasText: 'disabled' })).toContainText('disabled');
});

test('the state filter narrows the fleet', async ({ page }) => {
  await page.goto('/');
  const rows = page.locator('#listeners tbody tr:not(.detail-row)');
  await expect(rows.filter({ hasText: 'site-a' })).toHaveCount(1);

  await page.selectOption('#filter', 'error');
  await expect(rows.filter({ hasText: 'site-a' })).toHaveCount(0);
  await expect(rows.filter({ hasText: 'broken' })).toHaveCount(1);

  await page.selectOption('#filter', 'running');
  await expect(rows.filter({ hasText: 'broken' })).toHaveCount(0);
  await expect(rows.filter({ hasText: 'site-a' })).toHaveCount(1);

  await page.selectOption('#filter', '');
  await expect(rows.filter({ hasText: 'site-a' })).toHaveCount(1);
});

test('expanding a listener shows its config with secrets redacted and its peers', async ({ page }) => {
  await page.goto('/');
  await page.click('[data-expand="site-a"]');
  const cell = page.locator('[data-detail="site-a"]');

  // The config JSON renders the redaction sentinel, never the real key.
  await expect(cell).toContainText('"private-key": "<redacted>"');
  await expect(cell).not.toContainText(SEED_SECRET);

  // The seeded peer row is present, with a removal action (wireguard family).
  // Count is not pinned: a client-config test running earlier in the suite may
  // have provisioned additional peers onto site-a.
  await expect(cell).toContainText(SEED_PEER);
  await expect(cell.locator(`button[data-peer-key="${SEED_PEER}"]`)).toBeVisible();
});

test('an error listener shows its failure reason in the detail view', async ({ page }) => {
  await page.goto('/');
  await page.click('[data-expand="broken"]');
  await expect(page.locator('[data-detail="broken"]')).toContainText(
    'constructing toy server: user is required',
  );
});

// The peer-removal test is the one test that mutates a SEEDED entity rather than
// one it created, because the seeded peer is the only peer that exists before
// any test runs. It therefore has to put site-a's peer list back: without this
// the suite was green exactly once per harness process, and `--repeat-each=2`,
// a re-run of this file alone, or any local re-run against a surviving harness
// failed in two other files that read the same peer.
test.describe('peer removal', () => {
  test.afterEach(async ({ request }) => {
    const restored = await api(request, '/api/listeners/site-a', {
      method: 'PATCH',
      body: { options: { peers: SEED_PEERS_OPTION } },
    });
    expect(restored.status).toBe(200);
  });

  test('peer removal confirms, then takes the peer out of the config', async ({
    page,
    request,
  }) => {
    await page.goto('/');
    await page.click('[data-expand="site-a"]');
    const cell = page.locator('[data-detail="site-a"]');
    const seedRemove = cell.locator(`button[data-peer-key="${SEED_PEER}"]`);
    await expect(seedRemove).toBeVisible();

    // One handler that honours the current intent: a second page.on('dialog')
    // call would ADD a listener, not replace the first, and the earlier dismiss
    // handler would then swallow the accept path's dialog.
    let accept = false;
    page.on('dialog', (d) => (accept ? d.accept() : d.dismiss()));

    // A dismissed confirm leaves the peer alone -- in the DOM, and on disk. The
    // second assertion is the one that matters: a page that never re-rendered
    // satisfies the first one just as happily as a confirm that was honoured.
    accept = false;
    await seedRemove.click();
    await expect(seedRemove).toHaveCount(1);
    const afterDismiss = await api(request, '/api/listeners/site-a/peers');
    expect((afterDismiss.body as { peers: { id: string }[] }).peers.map((p) => p.id)).toContain(
      SEED_PEER,
    );

    // An accepted confirm removes it from the config; the row is gone. Other
    // provisioned peers may remain, so only the seeded peer's absence is
    // asserted.
    accept = true;
    await seedRemove.click();
    await expect(seedRemove).toHaveCount(0);
    await expect(cell).not.toContainText(SEED_PEER);
    const afterAccept = await api(request, '/api/listeners/site-a/peers');
    expect(
      (afterAccept.body as { peers: { id: string }[] }).peers.map((p) => p.id),
    ).not.toContain(SEED_PEER);
  });
});

// The audit log is what makes a "cancel does nothing" test mean anything. Both
// halves of a confirm() previously asserted the same two things -- banner hidden,
// row still running -- and the banner shows only on FAILURE, so deleting the
// `if (!confirm(...)) return;` guard left every assertion true. Counting the
// listener.restart events either side of each click asks the question the test
// is named for: did a request go out?
async function restartCount(request: APIRequestContext, name: string): Promise<number> {
  const res = await api(request, '/api/audit');
  const events = (res.body as { events?: { action: string; name: string }[] }).events ?? [];
  return events.filter((e) => e.action === 'listener.restart' && e.name === name).length;
}

test('restart confirms, and cancelling it sends no request', async ({ page, request }) => {
  await page.goto('/');
  const row = page.locator('#listeners tbody tr', { hasText: 'site-a' });
  const restart = row.locator('button[data-restart="site-a"]');
  const before = await restartCount(request, 'site-a');

  let accept = false;
  page.on('dialog', (d) => (accept ? d.accept() : d.dismiss()));

  // Cancel: no API call at all, so the audit trail is unchanged.
  accept = false;
  await restart.click();
  await expect(page.locator('#banner')).not.toHaveClass(/visible/);
  expect(await restartCount(request, 'site-a')).toBe(before);

  // Accept: the restart really happens and the listener keeps serving. (A second
  // page.on('dialog') would stack onto the first; the flag keeps one handler, so
  // the accept path is genuinely exercised.)
  accept = true;
  await restart.click();
  await expect(row).toContainText('running');
  await expect.poll(() => restartCount(request, 'site-a')).toBe(before + 1);
  await expect(page.locator('#banner')).not.toHaveClass(/visible/);
});

test('delete confirms, and cancelling it keeps the listener', async ({ page, request }) => {
  const name = uniqueName('tmpdel');
  const created = await api(request, '/api/listeners', {
    method: 'POST',
    body: { name, protocol: 'toy', options: { user: 'u', secret: 's' }, enabled: true },
  });
  expect(created.status).toBe(201);

  await page.goto('/');
  const row = page.locator('#listeners tbody tr', { hasText: name });
  await expect(row).toHaveCount(1);

  let accept = false;
  page.on('dialog', (d) => (accept ? d.accept() : d.dismiss()));

  // Dismiss: the row survives, and so does the listener. The name says the test
  // exercises dismiss; it did not, and a delete that ignored confirm() passed.
  accept = false;
  await page.locator(`button[data-delete="${name}"]`).click();
  await expect(row).toHaveCount(1);
  expect((await api(request, `/api/listeners/${name}`)).status).toBe(200);

  // Accept: gone from the page and gone from the API.
  accept = true;
  await page.locator(`button[data-delete="${name}"]`).click();
  await expect(row).toHaveCount(0);
  expect((await api(request, `/api/listeners/${name}`)).status).toBe(404);
});

test('the audit table records mutations and marks failures red', async ({ page, request }) => {
  const name = uniqueName('audit');
  const created = await api(request, '/api/listeners', {
    method: 'POST',
    body: { name, protocol: 'toy', options: { user: 'u', secret: 's' }, enabled: true },
  });
  expect(created.status).toBe(201);
  // A duplicate create fails; the audit row must carry the failure.
  const dup = await api(request, '/api/listeners', {
    method: 'POST',
    body: { name, protocol: 'toy', options: { user: 'u', secret: 's' }, enabled: true },
  });
  expect(dup.status).toBe(409);

  await page.goto('/');
  const table = page.locator('#audit tbody');
  // The failed duplicate create is the newest event and renders red.
  const first = table.locator('tr').first();
  await expect(first).toContainText(name);
  await expect(first).toContainText('listener.create');
  await expect(first.locator('.st-error')).toHaveCount(1);
  // The successful create is recorded too, and not red.
  const okRow = table.locator('tr').filter({ hasText: name }).filter({ hasText: 'ok' });
  await expect(okRow).toHaveCount(1);

  await api(request, `/api/listeners/${name}`, { method: 'DELETE' });
});

test('the log block shows the supervisor log tail', async ({ page }) => {
  await page.goto('/');
  const log = page.locator('#log');
  await expect(log).toContainText('supervisor ready: 2 of 5 listener(s) running');
  await expect(log).toContainText('constructing toy server: user is required');
});

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

test('peer removal confirms, then takes the peer out of the config', async ({ page }) => {
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

  // A dismissed confirm leaves the peer alone.
  accept = false;
  await seedRemove.click();
  await expect(seedRemove).toHaveCount(1);
  await expect(cell).toContainText(SEED_PEER);

  // An accepted confirm removes it from the config; the row is gone. Other
  // provisioned peers may remain, so only the seeded peer's absence is
  // asserted.
  accept = true;
  await seedRemove.click();
  await expect(seedRemove).toHaveCount(0);
  await expect(cell).not.toContainText(SEED_PEER);
});

test('restart confirms, and cancelling it does nothing', async ({ page }) => {
  await page.goto('/');
  const row = page.locator('#listeners tbody tr', { hasText: 'site-a' });
  const restart = row.locator('button[data-restart="site-a"]');

  let accept = false;
  page.on('dialog', (d) => (accept ? d.accept() : d.dismiss()));

  // Cancel: no API call, no banner, state unchanged.
  accept = false;
  await restart.click();
  await expect(page.locator('#banner')).not.toHaveClass(/visible/);
  await expect(row).toContainText('running');

  // Accept: the listener restarts and keeps serving. (A second page.on('dialog')
  // would stack onto the first; the flag keeps one handler, so the accept path
  // is genuinely exercised.)
  accept = true;
  await restart.click();
  await expect(page.locator('#banner')).not.toHaveClass(/visible/);
  await expect(row).toContainText('running');
});

test('delete confirms and removes a listener row', async ({ page, request }) => {
  const name = uniqueName('tmpdel');
  const created = await api(request, '/api/listeners', {
    method: 'POST',
    body: { name, protocol: 'toy', options: { user: 'u', secret: 's' }, enabled: true },
  });
  expect(created.status).toBe(201);

  await page.goto('/');
  await expect(page.locator('#listeners tbody tr', { hasText: name })).toHaveCount(1);
  page.on('dialog', (d) => d.accept());
  await page.locator(`button[data-delete="${name}"]`).click();
  await expect(page.locator('#listeners tbody tr', { hasText: name })).toHaveCount(0);
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
  await expect(log).toContainText('supervisor ready: 2 of 4 listener(s) running');
  await expect(log).toContainText('constructing toy server: user is required');
});

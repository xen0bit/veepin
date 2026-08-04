import { expect, test } from '@playwright/test';
import { api } from '../lib/api';
import { uniqueName } from '../lib/unique';

// Client-config generation from the dashboard's per-listener dialog: the
// WireGuard path mints a keypair, provisions a peer onto the listener, and
// offers the profile as a download. The dialog's overrides textarea is the
// escape hatch for per-host identity, and a malformed line must fail loudly.

test.describe.configure({ mode: 'serial' });

test('client-config generation provisions a peer and offers the profile', async ({
  page,
  request,
}) => {
  const before = await api(request, '/api/listeners/site-a/peers');
  expect(before.status).toBe(200);
  const beforeCount = (before.body as { peers: unknown[] }).peers.length;

  await page.goto('/');
  await page.click('[data-expand="site-a"]');
  const cell = page.locator('[data-detail="site-a"]');
  await expect(cell).toContainText('e2e-peer-AAAABBBBCCCCDDDDEEEEFFFF000011112222333344445555');

  await page.click('button[data-clientcfg="site-a"]');
  const dialog = page.locator('#cc-dialog');
  await expect(dialog).toBeVisible();
  await page.fill('#cc-endpoint', 'vpn.example.com');
  await page.click('#cc-ok');

  // The detail row now carries the generated profile and the provisioning
  // notice. The first free address past the server and the seeded peer is .3.
  await expect(cell).toContainText('profile.json');
  await expect(cell).toContainText('provisioned 1 peer');
  await expect(cell).toContainText('"address": "10.10.0.3/32"');
  // The generated profile carries the client's real key, not the redaction
  // sentinel. (The cell also shows the listener's own redacted config, so the
  // sentinel may still appear elsewhere; scoping this to the generated profile
  // is what the Go test TestClientConfigGeneratesProfile pins.)
  await expect(cell.locator('pre').first()).not.toContainText('<redacted>');

  // The peer really was provisioned onto the listener.
  const after = await api(request, '/api/listeners/site-a/peers');
  const afterPeers = (after.body as { peers: unknown[] }).peers;
  expect(afterPeers.length).toBe(beforeCount + 1);
});

test('the generated profile downloads as profile.json', async ({ page }) => {
  await page.goto('/');
  await page.click('[data-expand="site-a"]');
  await page.click('button[data-clientcfg="site-a"]');
  await page.fill('#cc-endpoint', 'vpn.example.com');
  await page.click('#cc-ok');

  const cell = page.locator('[data-detail="site-a"]');
  const link = cell.locator('a[download="profile.json"]');
  await expect(link).toHaveCount(1);

  const [download] = await Promise.all([page.waitForEvent('download'), link.click()]);
  expect(download.suggestedFilename()).toBe('profile.json');
});

test('generating without an endpoint fails in a banner', async ({ page }) => {
  await page.goto('/');
  await page.click('[data-expand="site-a"]');
  await page.click('button[data-clientcfg="site-a"]');
  // Leave the endpoint blank.
  await page.click('#cc-ok');

  await expect(page.locator('#banner')).toContainText('client config failed');
  await expect(page.locator('#banner')).toContainText('endpoint is required');
  await expect(page.locator('#cc-dialog')).toBeHidden();
});

test('a malformed override line is an error, not a silent drop', async ({ page }) => {
  await page.goto('/');
  await page.click('[data-expand="site-a"]');
  await page.click('button[data-clientcfg="site-a"]');
  await page.fill('#cc-endpoint', 'vpn.example.com');
  // A line with no "=" is a typo; the dialog must reject it before the API sees
  // it, and must stay open so the operator can fix it.
  await page.fill('#cc-overrides', 'address 10.99.0.5/32');
  await page.click('#cc-ok');

  await expect(page.locator('#banner')).toContainText('override line must be key=value');
  await expect(page.locator('#cc-dialog')).toBeVisible();
});

test('override values land in the generated profile', async ({ page, request }) => {
  // Use a fresh listener so the override test does not perturb site-a, and to
  // prove the override reaches the profile (10.99.0.5/32, not the allocated
  // .2 that provisioning chose).
  const name = uniqueName('wgovr');
  const created = await api(request, '/api/listeners', {
    method: 'POST',
    body: {
      name,
      protocol: 'wireguard',
      options: { 'private-key': '811WYV9bqgEduWyGDs+V+xJyo7Gx6Zo4Qn+HoB8Y6rk=', address: '10.30.0.1/24' },
      enabled: true,
    },
  });
  expect(created.status).toBe(201);

  await page.goto('/');
  await page.click(`[data-expand="${name}"]`);
  const cell = page.locator(`[data-detail="${name}"]`);
  await page.click(`button[data-clientcfg="${name}"]`);
  await page.fill('#cc-endpoint', 'vpn.example.com');
  await page.fill('#cc-overrides', 'address=10.99.0.5/32');
  await page.click('#cc-ok');

  // The override replaces the allocation in the GENERATED profile (the cell's
  // first pre). The listener itself still provisioned a peer from its subnet
  // and legitimately shows 10.30.0.2, so the negative assertion is scoped.
  const profile = cell.locator('pre').first();
  await expect(profile).toContainText('"address": "10.99.0.5/32"');
  await expect(profile).not.toContainText('10.30.0.2');

  await api(request, `/api/listeners/${name}`, { method: 'DELETE' });
});

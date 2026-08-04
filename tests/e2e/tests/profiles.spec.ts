import { expect, test } from '@playwright/test';
import { api } from '../lib/api';
import { uniqueName } from '../lib/unique';

// The profile add/edit page and the dashboard's profile table. Profiles are the
// client-side sibling of listeners: the form renders the client-protocol option
// surface, and secrets round-trip through the "<redacted>" sentinel.

test.describe.configure({ mode: 'serial' });

test('the dashboard lists the seeded profile', async ({ page }) => {
  await page.goto('/');
  const rows = page.locator('#profiles tbody tr');
  await expect(rows.filter({ hasText: 'home' })).toContainText('toy');
  await expect(rows.filter({ hasText: 'home' })).toContainText('delete');
});

test('the new profile form renders client protocols', async ({ page }) => {
  await page.goto('/profiles/new');

  // Profiles have no restart or delete either.
  await expect(page.locator('#apply')).toBeHidden();
  await expect(page.locator('#delete')).toBeHidden();

  // The dropdown is the client-protocol registry.
  const options = await page.locator('#protocol option').allTextContents();
  expect(options).toContain('toy');

  // The option surface is the client spec, not the server one: toy's client
  // declares a "server" key, while its server-only keys (listen, pool, dns)
  // must not render.
  await page.selectOption('#protocol', 'toy');
  await expect(page.locator('#opt-server')).toBeVisible();
  await expect(page.locator('#opt-listen')).toHaveCount(0);
  await expect(page.locator('#opt-pool')).toHaveCount(0);
  await expect(page.locator('#opt-dns')).toHaveCount(0);

  // Listener-only rows are hidden on the profile page.
  await expect(page.locator('#row-enabled')).toBeHidden();
  await expect(page.locator('#row-setup-nat')).toBeHidden();
  await expect(page.locator('#row-wan')).toBeHidden();
});

test('creating a profile through the form lands it on the dashboard', async ({
  page,
  request,
}) => {
  const name = uniqueName('prof');
  await page.goto('/profiles/new');
  await page.selectOption('#protocol', 'toy');
  await page.fill('#name', name);
  await page.fill('#opt-server', 'office.example.com');
  await page.fill('#opt-user', 'bob');
  await page.fill('#opt-secret', 's3cret');
  await page.click('#save');
  await page.waitForURL('/');

  const row = page.locator('#profiles tbody tr', { hasText: name });
  await expect(row).toContainText('toy');

  await api(request, `/api/profiles/${name}`, { method: 'DELETE' });
});

test('editing a profile preserves its secret through the redaction round trip', async ({
  page,
  request,
}) => {
  await page.goto('/profiles/home');
  await expect(page.locator('#name')).toHaveValue('home');
  // The stored secret is redacted in the form ...
  await expect(page.locator('#opt-secret')).toHaveValue('<redacted>');

  // ... and saving the form back (which submits "<redacted>") succeeds and
  // keeps the value on disk. The raw value is unreadable through the API by
  // design, so the preservation itself is pinned by the Go tests; what the
  // browser proves is that the sentinel round trip neither errors nor blanks.
  await page.click('#save');
  await page.waitForURL('/');

  const res = await api(request, '/api/profiles/home');
  expect(res.status).toBe(200);
  const opts = (res.body as { options: Record<string, string> }).options;
  expect(opts.secret).toBe('<redacted>');
});

test('deleting a profile confirms and removes it', async ({ page, request }) => {
  const name = uniqueName('profdel');
  const created = await api(request, '/api/profiles', {
    method: 'POST',
    body: { name, protocol: 'toy', options: { server: 'x.example.com', user: 'u', secret: 's' } },
  });
  expect(created.status).toBe(201);

  await page.goto('/');
  page.on('dialog', (d) => d.accept());
  await page.locator(`button[data-delprofile="${name}"]`).click();
  await expect(page.locator('#profiles tbody tr', { hasText: name })).toHaveCount(0);
});

test('creating a duplicate profile name is refused in a banner', async ({ page }) => {
  await page.goto('/profiles/new');
  await page.selectOption('#protocol', 'toy');
  await page.fill('#name', 'home');
  await page.fill('#opt-server', 'x.example.com');
  await page.fill('#opt-user', 'u');
  await page.fill('#opt-secret', 's');
  await page.click('#save');

  await expect(page.locator('#banner')).toContainText('already exists');
  await expect(page).toHaveURL(/\/profiles\/new$/);
});

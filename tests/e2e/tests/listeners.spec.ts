import { expect, test } from '@playwright/test';
import { api } from '../lib/api';
import { uniqueName } from '../lib/unique';

// The listener add/edit form: protocol-driven option fields, auto-generated key
// material surfaced once, the presence-aware PATCH round trip, the destructive
// actions, and the two failure shapes that must keep the operator on the page
// (a rejected create, and a 202 saved-but-rebuild-failed).

test.describe.configure({ mode: 'serial' });

test('the new listener form renders the protocol option surface', async ({ page }) => {
  await page.goto('/listeners/new');

  // New pages hide restart and delete: both would fire at an unsaved name.
  await expect(page.locator('#apply')).toBeHidden();
  await expect(page.locator('#delete')).toBeHidden();

  // The protocol dropdown is the server protocols registry.
  const options = await page.locator('#protocol option').allTextContents();
  expect(options).toContain('wireguard');
  expect(options).toContain('toy');

  await page.selectOption('#protocol', 'wireguard');
  // Declared options render as fields; secret keys carry the secret hint.
  await expect(page.locator('#opt-private-key')).toBeVisible();
  await expect(page.locator('#opt-address')).toBeVisible();
  // not.toHaveCount(0), not a one-shot .count(): the fields are rendered by the
  // protocol-change handler, so a bare count races the re-render and fails on a
  // slow machine for reasons that have nothing to do with the panel.
  await expect(page.locator('label.secret-hint')).not.toHaveCount(0);
  // wireguard's server spec marks nothing required (a wg-quick -config file can
  // supply everything), so no required markers should appear.
  await expect(page.locator('label.required')).toHaveCount(0);
});

test('creating a wireguard listener auto-generates keys and surfaces them once', async ({
  page,
  request,
}) => {
  const name = uniqueName('wg');
  await page.goto('/listeners/new');
  await page.selectOption('#protocol', 'wireguard');
  await page.fill('#name', name);
  await page.fill('#opt-address', '10.20.0.1/24');
  // Leave private-key empty: the API must mint one.
  await page.click('#save');

  // The generated public key is the operator's only copy, so the page waits.
  const generated = page.locator('#generated');
  await expect(generated).toBeVisible();
  await expect(generated).toContainText('generated key material');
  await expect(generated).toContainText('public-key');
  await expect(page).toHaveURL(/\/listeners\/new$/);

  await page.getByRole('button', { name: /I have copied it.*continue/ }).click();
  await page.waitForURL('/');

  // The listener is on the dashboard, running.
  const row = page.locator('#listeners tbody tr', { hasText: name });
  await expect(row).toContainText('running');

  await api(request, `/api/listeners/${name}`, { method: 'DELETE' });
});

test('creating a listener with an existing name shows the conflict in a banner', async ({
  page,
}) => {
  await page.goto('/listeners/new');
  await page.selectOption('#protocol', 'toy');
  await page.fill('#name', 'site-a');
  await page.fill('#opt-user', 'u');
  await page.fill('#opt-secret', 's');
  await page.click('#save');

  await expect(page.locator('#banner')).toContainText('a listener with that name already exists');
  await expect(page).toHaveURL(/\/listeners\/new$/);
});

test('creating a listener with an invalid name fails validation', async ({ page }) => {
  await page.goto('/listeners/new');
  await page.selectOption('#protocol', 'toy');
  await page.fill('#name', 'UPPERCASE');
  await page.fill('#opt-user', 'u');
  await page.fill('#opt-secret', 's');
  await page.click('#save');

  // The banner carries confstore's refusal verbatim, grammar included, so the
  // operator can see what a name is allowed to be rather than being told it was
  // wrong.
  await expect(page.locator('#banner')).toContainText('UPPERCASE');
  await expect(page.locator('#banner')).toContainText('^[a-z0-9][a-z0-9-]{0,31}$');
  await expect(page).toHaveURL(/\/listeners\/new$/);
});

// A reserved name is refused for a different reason and must say so. `mgmt` and
// `profiles` are the config root's own subdirectories, and a listener allowed to
// take one of those names had a DELETE that removed every client profile on the
// box -- and answered 404.
test('a listener named after a config-root directory is refused', async ({ page }) => {
  for (const name of ['mgmt', 'profiles']) {
    await page.goto('/listeners/new');
    await page.selectOption('#protocol', 'toy');
    await page.fill('#name', name);
    await page.fill('#opt-user', 'u');
    await page.fill('#opt-secret', 's');
    await page.click('#save');

    await expect(page.locator('#banner')).toContainText('the config root uses that name');
    await expect(page).toHaveURL(/\/listeners\/new$/);
  }
});

test('the edit page preloads an existing listener', async ({ page }) => {
  await page.goto('/listeners/site-a');

  const name = page.locator('#name');
  await expect(name).toHaveValue('site-a');
  await expect(name).toHaveAttribute('readonly', '');

  await expect(page.locator('#protocol')).toHaveValue('wireguard');
  await expect(page.locator('#opt-address')).toHaveValue('10.10.0.1/24');
  await expect(page.locator('#enabled')).toBeChecked();

  // The status line carries the live state from the API. tun0 is both what the
  // seed sets and what the fake manager derives on a rebuild, so this holds
  // whether or not an earlier test restarted site-a. (It previously claimed the
  // value came from a rebuild in another spec file -- a cross-file ordering
  // dependency that was not real, and that would have been a bad thing to rely
  // on if it were.)
  await expect(page.locator('#status')).toContainText('state=running');
  await expect(page.locator('#status')).toContainText('tun=tun0');

  // Edit pages keep the destructive actions.
  await expect(page.locator('#apply')).toBeVisible();
  await expect(page.locator('#delete')).toBeVisible();
});

test('editing a listener persists and shows the new value', async ({ page, request }) => {
  await page.goto('/listeners/site-a');
  await page.fill('#opt-address', '10.10.0.9/24');
  await page.click('#save');
  await page.waitForURL('/');

  await page.click('[data-expand="site-a"]');
  await expect(page.locator('[data-detail="site-a"]')).toContainText('10.10.0.9/24');

  // Restore the seeded value so later tests see a stable world. The form
  // submits every declared option including the redacted private-key, so this
  // save already proved the "<redacted>" sentinel is a no-op, not a clobber.
  const restored = await api(request, '/api/listeners/site-a', {
    method: 'PATCH',
    body: { options: { address: '10.10.0.1/24' } },
  });
  expect(restored.status).toBe(200);
});

test('disabling a listener through the edit page shows it stopped', async ({
  page,
  request,
}) => {
  const name = uniqueName('dis');
  const created = await api(request, '/api/listeners', {
    method: 'POST',
    body: { name, protocol: 'toy', options: { user: 'u', secret: 's' }, enabled: true },
  });
  expect(created.status).toBe(201);

  await page.goto(`/listeners/${name}`);
  await expect(page.locator('#enabled')).toBeChecked();
  await page.uncheck('#enabled');
  await page.click('#save');
  await page.waitForURL('/');

  const row = page.locator('#listeners tbody tr', { hasText: name });
  await expect(row).toContainText('disabled');

  await api(request, `/api/listeners/${name}`, { method: 'DELETE' });
});

test('the edit page can restart its listener', async ({ page }) => {
  await page.goto('/listeners/site-a');
  await page.click('#apply');
  await expect(page.locator('#status')).toContainText('restart -> 200');
});

test('the edit page can delete its listener', async ({ page, request }) => {
  const name = uniqueName('del');
  const created = await api(request, '/api/listeners', {
    method: 'POST',
    body: { name, protocol: 'toy', options: { user: 'u', secret: 's' }, enabled: true },
  });
  expect(created.status).toBe(201);

  await page.goto(`/listeners/${name}`);
  page.on('dialog', (d) => d.accept());
  await page.click('#delete');
  await page.waitForURL('/');

  await expect(page.locator('#listeners tbody tr', { hasText: name })).toHaveCount(0);
});

test('a failed rebuild surfaces a banner and does not redirect', async ({ page }) => {
  // "broken" is seeded with a rebuild failure, so a PATCH answers 202 with
  // build_error. The config IS saved; the panel must keep the page open.
  await page.goto('/listeners/broken');
  await expect(page.locator('#status')).toContainText('state=error');
  await page.fill('#opt-user', 'ops2');
  await page.click('#save');

  await expect(page.locator('#banner')).toContainText('saved, but the rebuild failed');
  await expect(page.locator('#banner')).toContainText('address in use');
  await expect(page).toHaveURL(/\/listeners\/broken$/);
});

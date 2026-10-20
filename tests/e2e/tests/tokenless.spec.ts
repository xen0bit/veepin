import { expect, test } from '@playwright/test';
import { TOKEN } from '../lib/config';

// The pages are served without authentication, and on loopback that means to
// every account on the host. If a page carried the token, any local user could
// read it and drive the root supervisor. These pin that it does not, and that
// the token an operator supplies in the fragment is taken from there.

test('no page the server renders contains the token', async ({ request }) => {
  for (const path of ['/', '/listeners/new', '/profiles/new', '/assets/panel.js']) {
    const res = await request.get(path);
    expect(res.status(), path).toBe(200);
    expect(await res.text(), path).not.toContain(TOKEN);
  }
});

test('a token in the fragment is used and then removed from the address bar', async ({ page }) => {
  await page.goto(`/#token=${encodeURIComponent(TOKEN)}`);
  await expect(page.locator('#listeners tbody tr').first()).not.toContainText('loading');
  expect(new URL(page.url()).hash).toBe('');
  const stored = await page.evaluate(() => sessionStorage.getItem('veepin-token'));
  expect(stored).toBe(TOKEN);
});

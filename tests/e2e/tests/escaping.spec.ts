import { expect, test } from '@playwright/test';
import { api } from '../lib/api';

// Escaping, asserted in a browser.
//
// This used to be a Go test that grepped dashboard.html for three literal
// spellings of `esc(...)`. That check passed for `'</td><td>'+l.error+'</td>'`
// written without spaces around the `+`, passed for a template literal, and
// could not have told the difference between an escaped value and an escaped
// value concatenated into an attribute where the escaping is wrong anyway. It
// asserted that some source text was present, which is not the property anyone
// cares about.
//
// The property anyone cares about is that a value the operator did not write --
// a protocol error quoting an option, a hostname from a config file -- cannot
// become markup. The panel holds the bearer token in its DOM, so markup landing
// in a row is a token-exfiltration path, not a cosmetic bug. A real browser is
// the only thing that can answer whether it did.
//
// The seeded `markup` listener carries the payloads: an error that would run
// `window.__xss_error = 1`, an option value that would run `window.__xss_option
// = 1`, and an option value that would close the table cell it lives in.

// A payload that fires sets a property on window; if the escaping holds, both
// stay undefined. Reading them is the assertion -- "no <img> in the row" would
// pass against a payload that used a different tag.
async function xssFlags(page: import('@playwright/test').Page) {
  return page.evaluate(() => ({
    error: (window as unknown as { __xss_error?: number }).__xss_error,
    option: (window as unknown as { __xss_option?: number }).__xss_option,
  }));
}

test('an error containing markup renders as text, not as markup', async ({ page }) => {
  await page.goto('/');
  const row = page.locator('#listeners tbody tr:not(.detail-row)', { hasText: 'markup' });

  // The payload is visible as its literal characters.
  await expect(row).toContainText('<img src=x onerror=window.__xss_error=1>');
  // And it is not an element.
  await expect(row.locator('img')).toHaveCount(0);
  // The closing-tag payload did not split the row into extra cells. The table
  // has a fixed column count; an injected </td><td> would add one.
  const header = await page.locator('#listeners thead th').count();
  expect(await row.locator('td').count()).toBe(header);

  expect(await xssFlags(page)).toEqual({ error: undefined, option: undefined });
});

test('option values containing markup render as text in the detail view', async ({ page }) => {
  await page.goto('/');
  await page.click('[data-expand="markup"]');
  const cell = page.locator('[data-detail="markup"]');

  await expect(cell).toContainText('<script>window.__xss_option=1</script>');
  await expect(cell.locator('script')).toHaveCount(0);
  await expect(cell).toContainText('</td><td>injected');

  // The error is repeated in the detail view's own error block; it must be text
  // there too, and that block is built by a different line of dashboard.js.
  await expect(cell).toContainText('no such host');
  await expect(cell.locator('img')).toHaveCount(0);

  expect(await xssFlags(page)).toEqual({ error: undefined, option: undefined });
});

test('a listener name a payload rides in cannot escape the audit table', async ({
  page,
  request,
}) => {
  // Listener names are grammar-constrained, so the audit table's payload has to
  // arrive through the outcome: a create that fails quotes what it refused.
  const bad = '<img src=x onerror=window.__xss_audit=1>';
  const rejected = await api(request, '/api/listeners', {
    method: 'POST',
    body: { name: bad, protocol: 'toy', options: { user: 'u' }, enabled: true },
  });
  expect(rejected.status).toBe(400);

  await page.goto('/');
  const audit = page.locator('#audit tbody');
  await expect(audit.locator('tr').first()).toContainText('listener.create');
  await expect(audit.locator('img')).toHaveCount(0);
  expect(
    await page.evaluate(() => (window as unknown as { __xss_audit?: number }).__xss_audit),
  ).toBeUndefined();
});

test('a log line containing markup renders as text', async ({ page }) => {
  // The log tail carries protocol errors verbatim, and protocol errors quote
  // option values, so a hostname out of a config file reaches the page. The
  // payload is seeded rather than provoked: a test that hopes an error will
  // quote what it wanted, and asserts "no <img> present" either way, passes just
  // as happily when nothing reached the log at all.
  await page.goto('/');
  const log = page.locator('#log');

  await expect(log).toContainText('<img src=x onerror=window.__xss_log=1>');
  await expect(log.locator('img')).toHaveCount(0);
  expect(
    await page.evaluate(() => (window as unknown as { __xss_log?: number }).__xss_log),
  ).toBeUndefined();
});

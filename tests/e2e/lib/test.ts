import { test as base, expect } from '@playwright/test';
import { TOKEN } from './config';

// The panel's pages carry no bearer token: an operator brings it, as #token=
// in the URL or pasted into a prompt, and panel.js keeps it in sessionStorage.
// Every spec's page starts with it already there, the state an operator is in
// after the first visit, so the specs exercise the panel rather than the
// sign-in. tokenless.spec.ts covers the sign-in itself.
export const test = base.extend({
  page: async ({ page }, use) => {
    await page.addInitScript((token) => {
      try {
        if (!sessionStorage.getItem('veepin-token')) sessionStorage.setItem('veepin-token', token);
      } catch {
        // A browser with storage disabled: the panel would prompt instead.
      }
    }, TOKEN);
    await use(page);
  },
});

export { expect };

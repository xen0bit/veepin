// Shared constants between the Playwright config's webServer command and the
// specs. They mirror the harness flags' defaults; a dev overriding one of the
// env vars gets both sides for free.
export const ADDR = process.env.PANEL_ADDR ?? '127.0.0.1:18555';
export const TOKEN = process.env.PANEL_TOKEN ?? 'veepin-e2e-token';

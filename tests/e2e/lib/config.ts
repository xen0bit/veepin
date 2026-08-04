// The one constant the Playwright config's webServer command and the specs both
// need; a dev overriding PANEL_TOKEN gets both sides for free.
//
// The address is deliberately not here. The config picks a free port at load
// time, so there is no address a spec could import and be sure it is the one the
// harness bound. Specs use relative URLs, which `use.baseURL` resolves against
// whatever the config chose.
export const TOKEN = process.env.PANEL_TOKEN ?? 'veepin-e2e-token';

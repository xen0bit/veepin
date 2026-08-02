import type { APIRequestContext } from '@playwright/test';
import { TOKEN } from './config';

// api is a tiny typed client for the management API, used for setup, cleanup,
// and the assertions that complement the DOM ones (e.g. "the secret really
// survived" needs the raw endpoint, which only an HTTP call can reach). It
// mirrors the panel's own helper: read the body as text, fall back to JSON, so
// a plain-text http.Error response surfaces as {status, body: string}.

export interface ApiResult {
  status: number;
  body: unknown;
}

export function api(
  request: APIRequestContext,
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<ApiResult> {
  return request
    .fetch(path, {
      method: init.method ?? 'GET',
      headers: {
        Authorization: `Bearer ${TOKEN}`,
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      data: init.body,
    })
    .then(async (res) => {
      const text = await res.text();
      let body: unknown = text;
      try {
        body = JSON.parse(text);
      } catch {
        // leave the raw text
      }
      return { status: res.status(), body };
    });
}

// panel.js — shared helpers for the supervisor's server-rendered pages. Both
// templates set window.VEEPIN_TOKEN before loading this file; everything below
// is page-agnostic.

// api issues one authenticated fetch and resolves to {status, body}, parsing
// whichever body the server sent. The API answers some errors with plain text
// (http.Error) and some with JSON; reading the text first means a rejected
// request lands in the caller's error handling rather than rejecting the
// promise and doing nothing visible.
function api(path, opts) {
  opts = Object.assign({}, opts || {});
  opts.headers = Object.assign({"Authorization": "Bearer " + window.VEEPIN_TOKEN}, opts.headers || {});
  if (opts.body !== undefined && typeof opts.body !== "string") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  return fetch(path, opts).then(r => r.text().then(t => {
    let body = t;
    try { body = JSON.parse(t); } catch (e) {}
    return {status: r.status, body};
  }));
}

// esc makes a value safe to concatenate into innerHTML. Every field a page
// renders goes through it: listener `error` is arbitrary text from a protocol's
// failure path that routinely quotes the option values that caused it, and
// these pages hold the bearer token in their DOM, so markup landing in them is
// a token-exfiltration path.
function esc(v) {
  return String(v === undefined || v === null ? "" : v)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

// showBanner puts message into the page's error banner (an element with
// class="banner"), making the most recent failure the visible outcome rather
// than a silent no-op.
function showBanner(el, message) {
  if (!el) return;
  el.textContent = message;
  el.classList.add("visible");
}

function clearBanner(el) {
  if (el) el.classList.remove("visible");
}

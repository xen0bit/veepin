// panel.js — shared helpers for the supervisor's server-rendered pages.
// Everything below is page-agnostic.

// The bearer token never arrives in a page: the server renders these to anyone
// who can reach the port. The operator brings it -- as #token=... in the URL,
// which a browser never sends to the server, or pasted into the prompt below --
// and it is kept in sessionStorage for this tab only. The fragment is removed
// from the address bar as soon as it is read, so it does not linger in history
// or get copied along with the URL.
const TOKEN_KEY = "veepin-token";

function panelToken() {
  const m = /(?:^#|&)token=([^&]+)/.exec(location.hash);
  if (m) {
    const t = decodeURIComponent(m[1]);
    try { sessionStorage.setItem(TOKEN_KEY, t); } catch (e) {}
    history.replaceState(null, "", location.pathname + location.search);
    return t;
  }
  try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch (e) { return ""; }
}

window.VEEPIN_TOKEN = panelToken();

// askForToken prompts once for a token after the API refuses the one held (or
// the lack of one), stores it, and reloads so every view fetches afresh.
let asked = false;
function askForToken() {
  if (asked) return;
  asked = true;
  const t = window.prompt("Paste the management token (the contents of <config>/mgmt/token):");
  if (!t) return;
  try { sessionStorage.setItem(TOKEN_KEY, t.trim()); } catch (e) {}
  location.reload();
}

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
    if (r.status === 401) askForToken();
    let body = t;
    try { body = JSON.parse(t); } catch (e) {}
    return {status: r.status, body};
  }));
}

// esc makes a value safe to concatenate into innerHTML. Every field a page
// renders goes through it: listener `error` is arbitrary text from a protocol's
// failure path that routinely quotes the option values that caused it, and
// these pages hold the bearer token in their script state, so markup landing
// in them is a token-exfiltration path.
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

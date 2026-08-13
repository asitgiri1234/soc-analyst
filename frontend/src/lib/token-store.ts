/**
 * Where the access token lives.
 *
 * In memory, mirrored into `sessionStorage` so a page reload does not force a
 * fresh login. `sessionStorage` rather than `localStorage` deliberately: it is
 * scoped to the tab and dropped when the tab closes, so a shared machine does
 * not keep a usable SOC session alive in a browser nobody is watching.
 *
 * This is a bearer token in JavaScript-reachable storage, which is only as safe
 * as the app is free of XSS. The mitigation is that nothing in this app renders
 * untrusted content as HTML -- React escapes by default and no component uses
 * `dangerouslySetInnerHTML`. An httpOnly cookie would be stronger, but the
 * backend issues bearer tokens and inventing a cookie session in the frontend
 * would put an auth mechanism in the wrong tier.
 *
 * The expiry is tracked alongside so a token known to be dead is never sent.
 */

const TOKEN_KEY = "soc.access_token";
const EXPIRY_KEY = "soc.access_token_expires_at";

let token: string | null = null;
let expiresAt: number | null = null;
let loaded = false;

type Listener = () => void;
const listeners = new Set<Listener>();

function notify(): void {
  for (const listener of listeners) listener();
}

/** Subscribe to token changes; returns an unsubscribe function. */
export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Read the persisted token once, on first access in the browser. */
function hydrate(): void {
  if (loaded || typeof window === "undefined") return;
  loaded = true;
  const stored = window.sessionStorage.getItem(TOKEN_KEY);
  const storedExpiry = window.sessionStorage.getItem(EXPIRY_KEY);
  if (stored && storedExpiry) {
    token = stored;
    expiresAt = Number(storedExpiry);
  }
}

export function getToken(): string | null {
  hydrate();
  if (token && expiresAt !== null && Date.now() >= expiresAt) {
    // Expired while the tab sat idle. Drop it rather than send a token the
    // server will only reject.
    clearToken();
    return null;
  }
  return token;
}

export function setToken(value: string, expiresInSeconds: number): void {
  loaded = true;
  token = value;
  expiresAt = Date.now() + expiresInSeconds * 1000;
  if (typeof window !== "undefined") {
    window.sessionStorage.setItem(TOKEN_KEY, value);
    window.sessionStorage.setItem(EXPIRY_KEY, String(expiresAt));
  }
  notify();
}

export function clearToken(): void {
  loaded = true;
  token = null;
  expiresAt = null;
  if (typeof window !== "undefined") {
    window.sessionStorage.removeItem(TOKEN_KEY);
    window.sessionStorage.removeItem(EXPIRY_KEY);
  }
  notify();
}

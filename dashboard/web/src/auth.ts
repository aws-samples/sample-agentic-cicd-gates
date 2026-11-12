// Sign-in with Amazon Cognito managed login: OAuth 2.0 authorization code grant
// with PKCE (S256) for a public client. No dependencies.
//
// What is stored, and where: only the access token and its expiry, in
// sessionStorage (cleared when the tab closes). The ID and refresh tokens that
// Cognito also returns are discarded. While a sign-in is in flight, the random
// state, the PKCE verifier and the page's query string (deep-link selections)
// are kept in sessionStorage and removed when the user returns.

export type AuthConfig = {
  region: string;
  domain: string;        // https://<prefix>.auth.<region>.amazoncognito.com
  client_id: string;
  redirect_uri: string;  // the dashboard base URL
};

const TOKEN_KEY = 'dashboard.auth.token';
const PENDING_KEY = 'dashboard.auth.pending';
const EXPIRY_SKEW_MS = 30_000;

type StoredToken = { access_token: string; expires_at: number };
type Pending = { state: string; verifier: string; search: string };

let config: Promise<AuthConfig> | undefined;

export function authConfig(): Promise<AuthConfig> {
  config ??= fetch('/auth-config', { cache: 'no-store' }).then(async r => {
    if (!r.ok) throw new Error(`Sign-in configuration unavailable (HTTP ${r.status})`);
    const c = await r.json() as AuthConfig;
    if (!c.domain?.startsWith('https://') || !c.client_id || !c.redirect_uri) {
      throw new Error('Sign-in is not configured for this dashboard');
    }
    return c;
  });
  return config;
}

function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function random(n: number): string {
  return b64url(crypto.getRandomValues(new Uint8Array(n)));
}

async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

function read<T>(key: string): T | undefined {
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? JSON.parse(raw) as T : undefined;
  } catch {
    return undefined;
  }
}

/** The stored access token, if it has not expired. */
export function accessToken(): string | undefined {
  const t = read<StoredToken>(TOKEN_KEY);
  if (!t || typeof t.access_token !== 'string' || !(t.expires_at > Date.now() + EXPIRY_SKEW_MS)) return undefined;
  return t.access_token;
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

/** Redirect to managed login. Keeps the current selections for the return trip. */
export async function signIn(): Promise<never> {
  const c = await authConfig();
  const keep = new URLSearchParams(location.search);
  for (const k of ['code', 'state', 'error', 'error_description']) keep.delete(k);
  const search = keep.toString() ? `?${keep}` : '';
  const pending: Pending = { state: random(32), verifier: random(64), search };
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
  const url = new URL('/oauth2/authorize', c.domain);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: c.client_id,
    redirect_uri: c.redirect_uri,
    scope: 'openid email',
    state: pending.state,
    code_challenge_method: 'S256',
    code_challenge: await s256(pending.verifier),
  }).toString();
  location.assign(url.toString());
  return new Promise<never>(() => { /* the page is navigating away */ });
}

/**
 * Clear everything this module stored and end the Cognito session. The local
 * sign-out always happens; if the sign-in configuration cannot be loaded, the
 * page reloads and the next data request starts a new sign-in.
 */
export async function signOut(): Promise<void> {
  clearToken();
  sessionStorage.removeItem(PENDING_KEY);
  try {
    const c = await authConfig();
    const url = new URL('/logout', c.domain);
    url.search = new URLSearchParams({ client_id: c.client_id, logout_uri: c.redirect_uri }).toString();
    location.assign(url.toString());
  } catch {
    location.reload();
  }
}

/** Exchange ?code=&state= for an access token, then restore the saved query. */
async function completeSignIn(c: AuthConfig, params: URLSearchParams): Promise<void> {
  const pending = read<Pending>(PENDING_KEY);
  sessionStorage.removeItem(PENDING_KEY);
  const base = new URL(c.redirect_uri).pathname;
  // The code and state never stay in the address bar or the history entry.
  history.replaceState(null, '', base + (pending?.search ?? ''));
  const error = params.get('error');
  if (error) throw new Error(`Sign-in failed: ${params.get('error_description') || error}`);
  if (!pending || pending.state !== params.get('state')) {
    throw new Error('Sign-in response did not match this browser session');
  }
  const r = await fetch(new URL('/oauth2/token', c.domain), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: c.client_id,
      code: params.get('code') ?? '',
      redirect_uri: c.redirect_uri,
      code_verifier: pending.verifier,
    }),
  });
  if (!r.ok) throw new Error(`Sign-in token exchange failed (HTTP ${r.status})`);
  const body = await r.json() as { access_token?: string; expires_in?: number };
  if (!body.access_token || !(Number(body.expires_in) > 0)) throw new Error('Sign-in returned no access token');
  const stored: StoredToken = { access_token: body.access_token, expires_at: Date.now() + Number(body.expires_in) * 1000 };
  sessionStorage.setItem(TOKEN_KEY, JSON.stringify(stored));
}

/**
 * Resolve once a usable access token is stored. Starts or finishes the
 * sign-in redirect as needed; rejects with a readable error on failure.
 */
export async function ensureSignedIn(): Promise<void> {
  const params = new URLSearchParams(location.search);
  const returning = (params.has('code') && params.has('state')) || params.has('error');
  if (returning && read<Pending>(PENDING_KEY)) {
    await completeSignIn(await authConfig(), params);
    return;
  }
  if (accessToken()) return;
  await signIn();
}

/** fetch() with the access token. A 401 clears the token and signs in again. */
export async function authorizedFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const token = accessToken();
  if (!token) return signIn();
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${token}`);
  const r = await fetch(input, { ...init, headers });
  if (r.status === 401) {
    clearToken();
    return signIn();
  }
  return r;
}

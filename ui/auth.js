/**
 * auth.js — browser SDK for awesome-go-auth.
 * Vanilla JS, no dependencies.
 *
 * It speaks the family wire contract this library's own adapters serve:
 *
 *   - Cookie delivery by default. Every request carries `credentials:'include'`
 *     and mirrors the CSRF cookie into `X-CSRF-Token`, reading it with the
 *     family's `__Host-` → `__Secure-` → bare priority. This is what the
 *     reference client does, and it is the server's default.
 *   - Bearer delivery on request. `configure({bearer:true})` sends
 *     `X-Auth-Strategy: bearer` (exact and case-sensitive — the server compares
 *     it literally), which makes the token-issuing routes answer with
 *     `accessToken`/`refreshToken` in the body and set no cookies. Use it for a
 *     page served from a different origin than the API, where cookies will not
 *     travel.
 *   - Response envelopes are `{"success": true}` plus whatever the route adds.
 *     There is no `tokens` object and there are no snake_case fields.
 *   - A missing or unusable access token is 403, not 401. Both are treated as
 *     "try a refresh", except when the body carries `code: "SESSION_REVOKED"` —
 *     that one is permanent and retrying loops forever.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AuthSDK = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const ACCESS_KEY = 'auth_access_token';
  const REFRESH_KEY = 'auth_refresh_token';

  const CSRF_COOKIES = ['__Host-csrf-token', '__Secure-csrf-token', 'csrf-token'];

  let _baseURL = '';
  let _prefix = '/auth';
  let _bearer = false;
  let _refreshTimer = null;
  let _refreshInFlight = null;

  /**
   * configure sets the API location and the delivery mode.
   *
   *   baseURL   origin of the auth server; empty means same-origin
   *   apiPrefix where the routes are mounted; defaults to /auth
   *   bearer    true to use header/localStorage delivery instead of cookies
   */
  function configure(options) {
    if (!options) return;
    if (typeof options.baseURL === 'string') _baseURL = options.baseURL.replace(/\/$/, '');
    if (typeof options.apiPrefix === 'string' && options.apiPrefix) {
      _prefix = '/' + options.apiPrefix.replace(/^\/+|\/+$/g, '');
    }
    if (typeof options.bearer === 'boolean') _bearer = options.bearer;
  }

  // ─── credentials ───────────────────────────────────────────────────────────

  function getCookie(name) {
    const match = document.cookie.match(new RegExp('(^|;\\s*)' + name.replace(/[-]/g, '\\$&') + '=([^;]*)'));
    return match ? decodeURIComponent(match[2]) : null;
  }

  // csrfToken applies the family's cookie read priority. Every read site has to
  // use it, or a deployment that switches the Secure flag stops recognising its
  // own cookie.
  function csrfToken() {
    for (const name of CSRF_COOKIES) {
      const value = getCookie(name);
      if (value) return value;
    }
    return null;
  }

  function storeTokens(data) {
    if (!data) return;
    if (data.accessToken) localStorage.setItem(ACCESS_KEY, data.accessToken);
    if (data.refreshToken) localStorage.setItem(REFRESH_KEY, data.refreshToken);
    scheduleRefresh();
  }

  function clearTokens() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
  }

  function getAccessToken() { return localStorage.getItem(ACCESS_KEY); }
  function getRefreshToken() { return localStorage.getItem(REFRESH_KEY); }

  function tokenExpiry(token) {
    try {
      const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      return payload.exp ? payload.exp * 1000 : null;
    } catch (_) { return null; }
  }

  /**
   * isLoggedIn is only meaningful in bearer mode. In cookie mode the token is
   * HttpOnly and unreadable by design, so this cannot tell — call me() instead.
   */
  function isLoggedIn() {
    const token = getAccessToken();
    if (!token) return false;
    const exp = tokenExpiry(token);
    return exp === null ? true : exp > Date.now();
  }

  // scheduleRefresh renews shortly before the access token expires. The expiry
  // comes from the token itself: the response body no longer carries a lifetime.
  // Cookie mode does not schedule at all — the token is unreadable, and the
  // 401/403 handler below refreshes reactively instead.
  function scheduleRefresh() {
    if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
    if (!_bearer) return;
    const token = getAccessToken();
    if (!token) return;
    const exp = tokenExpiry(token);
    if (!exp) return;
    _refreshTimer = setTimeout(function () {
      refresh().catch(function () {
        clearTokens();
        window.dispatchEvent(new CustomEvent('auth:expired'));
      });
    }, Math.max(exp - Date.now() - 30000, 5000));
  }

  // ─── transport ─────────────────────────────────────────────────────────────

  function url(path) { return _baseURL + _prefix + path; }

  function buildInit(method, body, opts) {
    const options = opts || {};
    const headers = Object.assign({}, options.headers);
    if (body !== undefined && body !== null) headers['Content-Type'] = 'application/json';

    if (_bearer) {
      headers['X-Auth-Strategy'] = 'bearer';
      const token = getAccessToken();
      if (token && !options.skipAuth) headers['Authorization'] = 'Bearer ' + token;
    } else {
      // Double-submit: the server only enforces it on cookie-authenticated
      // requests to routes behind the auth gate, but sending it always is
      // harmless and saves every call site from having to know which is which.
      const token = csrfToken();
      if (token) headers['X-CSRF-Token'] = token;
    }

    const init = { method, headers };
    if (!_bearer) init.credentials = 'include';
    if (body !== undefined && body !== null) init.body = JSON.stringify(body);
    return init;
  }

  async function parse(resp) {
    const data = await resp.json().catch(function () { return {}; });
    if (!resp.ok) {
      const err = new Error((data && data.error) || resp.statusText || 'Request failed');
      err.status = resp.status;
      err.code = data && data.code;
      err.data = data;
      throw err;
    }
    return data;
  }

  // refreshOnce collapses concurrent refreshes into one in-flight call, so a
  // page that fires several requests at the moment of expiry does not rotate the
  // refresh token N times and invalidate its own session.
  function refreshOnce() {
    if (_refreshInFlight) return _refreshInFlight;
    _refreshInFlight = (async function () {
      const body = _bearer ? { refreshToken: getRefreshToken() } : null;
      const resp = await fetch(url('/refresh'), buildInit('POST', body, { skipAuth: true }));
      const data = await parse(resp);
      if (_bearer) storeTokens(data);
      return data;
    })().finally(function () { _refreshInFlight = null; });
    return _refreshInFlight;
  }

  // Routes that must never trigger the refresh-and-retry path: a 401 from them
  // is the answer, not a stale-token symptom, and retrying would loop.
  const NO_RETRY = ['/login', '/register', '/refresh', '/logout'];

  async function request(method, path, body, opts) {
    const options = opts || {};
    const resp = await fetch(url(path), buildInit(method, body, options));

    const retryable = !options.noRetry && !NO_RETRY.includes(path) &&
      (resp.status === 401 || resp.status === 403);
    if (!retryable) return parse(resp);

    // A revoked session is permanent: both browser clients in this family log
    // out on exactly this code rather than refreshing.
    let peeked = null;
    try { peeked = await resp.clone().json(); } catch (_) { /* not JSON */ }
    if (peeked && peeked.code === 'SESSION_REVOKED') {
      clearTokens();
      window.dispatchEvent(new CustomEvent('auth:expired', { detail: peeked }));
      return parse(resp);
    }

    try {
      await refreshOnce();
    } catch (_) {
      clearTokens();
      window.dispatchEvent(new CustomEvent('auth:expired'));
      return parse(resp);
    }
    return parse(await fetch(url(path), buildInit(method, body, options)));
  }

  // ─── core ──────────────────────────────────────────────────────────────────

  async function register(email, password, tenantId) {
    const data = await request('POST', '/register', { email, password, tenantId: tenantId || '' });
    storeTokens(data);
    window.dispatchEvent(new CustomEvent('auth:register', { detail: data }));
    return data;
  }

  async function login(email, password, tenantId) {
    const data = await request('POST', '/login', { email, password, tenantId: tenantId || '' });
    storeTokens(data);
    window.dispatchEvent(new CustomEvent('auth:login', { detail: data }));
    return data;
  }

  /** logout always succeeds server-side, even without a credential. */
  async function logout() {
    try {
      await request('POST', '/logout', _bearer ? { refreshToken: getRefreshToken() } : null, { noRetry: true });
    } catch (_) { /* the caller is logged out either way */ }
    clearTokens();
    window.dispatchEvent(new CustomEvent('auth:logout'));
  }

  async function refresh() { return refreshOnce(); }

  /** me returns the user object itself — it is not wrapped in an envelope. */
  async function me() { return request('GET', '/me'); }

  // ─── sessions and account ──────────────────────────────────────────────────

  async function listSessions() { return request('GET', '/sessions'); }
  async function revokeSession(handle) { return request('DELETE', '/sessions/' + encodeURIComponent(handle)); }
  async function cleanupSessions() { return request('POST', '/sessions/cleanup'); }
  async function updateProfile(profile) { return request('PATCH', '/profile', profile || {}); }
  async function addPhone(phoneNumber) { return request('POST', '/add-phone', { phoneNumber }); }

  async function deleteAccount() {
    const data = await request('DELETE', '/account');
    clearTokens();
    window.dispatchEvent(new CustomEvent('auth:logout'));
    return data;
  }

  // ─── password and email ────────────────────────────────────────────────────

  async function forgotPassword(email, tenantId, emailLang) {
    return request('POST', '/forgot-password', { email, tenantId: tenantId || '', emailLang: emailLang || '' });
  }

  /** The field is `password`, not `newPassword` — the family's clients send that. */
  async function resetPassword(token, password) {
    return request('POST', '/reset-password', { token, password });
  }

  async function changePassword(currentPassword, newPassword) {
    return request('POST', '/change-password', { currentPassword, newPassword });
  }

  async function sendVerificationEmail(emailLang) {
    return request('POST', '/send-verification-email', { emailLang: emailLang || '' });
  }

  /** A GET, because the link is opened from a mailbox. */
  async function verifyEmail(token) {
    return request('GET', '/verify-email?token=' + encodeURIComponent(token));
  }

  async function requestEmailChange(newEmail, emailLang) {
    return request('POST', '/change-email/request', { newEmail, emailLang: emailLang || '' });
  }

  async function confirmEmailChange(token) {
    return request('POST', '/change-email/confirm', { token });
  }

  // ─── passwordless ──────────────────────────────────────────────────────────
  //
  // `mode` is compared literally against "2fa" by the server; anything else,
  // including its absence, means login. Passing tempToken selects the step-up
  // branch, which is the only branch that accepts one.

  async function sendMagicLink(email, tenantId, tempToken) {
    const body = tempToken ? { mode: '2fa', tempToken } : { email, tenantId: tenantId || '' };
    return request('POST', '/magic-link/send', body);
  }

  async function verifyMagicLink(token, tempToken) {
    const body = tempToken ? { token, mode: '2fa', tempToken } : { token };
    const data = await request('POST', '/magic-link/verify', body);
    storeTokens(data);
    window.dispatchEvent(new CustomEvent('auth:login', { detail: data }));
    return data;
  }

  async function sendSMSCode(identity, tenantId, tempToken) {
    const body = tempToken
      ? { mode: '2fa', tempToken }
      : Object.assign(
        String(identity || '').includes('@') ? { email: identity } : { userId: identity },
        { tenantId: tenantId || '' },
      );
    return request('POST', '/sms/send', body);
  }

  async function verifySMSCode(userId, code, tenantId, tempToken) {
    const body = tempToken
      ? { code, mode: '2fa', tempToken }
      : { userId, code, tenantId: tenantId || '' };
    const data = await request('POST', '/sms/verify', body);
    storeTokens(data);
    window.dispatchEvent(new CustomEvent('auth:login', { detail: data }));
    return data;
  }

  // ─── second factor ─────────────────────────────────────────────────────────
  //
  // The three routes disagree on what the code field is called, and the clients
  // are written against the disagreement: verify-setup takes `token`, verify
  // takes `totpCode`.

  async function setupTwoFactor() { return request('POST', '/2fa/setup'); }

  async function verifyTwoFactorSetup(secret, token) {
    return request('POST', '/2fa/verify-setup', { secret, token });
  }

  async function verifyTwoFactor(tempToken, totpCode) {
    const data = await request('POST', '/2fa/verify', { tempToken, totpCode });
    storeTokens(data);
    window.dispatchEvent(new CustomEvent('auth:login', { detail: data }));
    return data;
  }

  async function disableTwoFactor() { return request('POST', '/2fa/disable'); }

  // ─── OAuth and account linking ─────────────────────────────────────────────

  /** oauthURL is a full-page navigation target, not a fetch. */
  function oauthURL(provider) { return url('/oauth/' + encodeURIComponent(provider)); }
  function startOAuth(provider) { window.location.href = oauthURL(provider); }

  async function listLinkedAccounts() { return request('GET', '/linked-accounts'); }

  async function unlinkAccount(provider, providerAccountId) {
    return request('DELETE', '/linked-accounts/' + encodeURIComponent(provider) + '/' + encodeURIComponent(providerAccountId));
  }

  async function requestAccountLink(email) { return request('POST', '/link-request', { email }); }
  async function verifyAccountLink(token) { return request('POST', '/link-verify', { token }); }

  // ─── SSE helper ────────────────────────────────────────────────────────────

  function connectSSE(path, onMessage) {
    // EventSource cannot set headers, so a bearer deployment has to pass the
    // token in the query string; a cookie deployment needs withCredentials.
    const token = _bearer ? getAccessToken() : null;
    const target = _baseURL + path + (token ? '?token=' + encodeURIComponent(token) : '');
    const es = new EventSource(target, { withCredentials: !_bearer });
    es.addEventListener('message', function (e) {
      try { onMessage(JSON.parse(e.data)); } catch (_) { onMessage(e.data); }
    });
    return es;
  }

  return {
    configure,
    storeTokens,
    clearTokens,
    getAccessToken,
    getRefreshToken,
    isLoggedIn,
    register,
    login,
    logout,
    refresh,
    me,
    listSessions,
    revokeSession,
    cleanupSessions,
    updateProfile,
    addPhone,
    deleteAccount,
    forgotPassword,
    resetPassword,
    changePassword,
    sendVerificationEmail,
    verifyEmail,
    requestEmailChange,
    confirmEmailChange,
    sendMagicLink,
    verifyMagicLink,
    sendSMSCode,
    verifySMSCode,
    setupTwoFactor,
    verifyTwoFactorSetup,
    verifyTwoFactor,
    disableTwoFactor,
    oauthURL,
    startOAuth,
    listLinkedAccounts,
    unlinkAccount,
    requestAccountLink,
    verifyAccountLink,
    connectSSE,
    request,
  };
}));

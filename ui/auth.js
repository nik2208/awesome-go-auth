/**
 * auth.js - Browser SDK for awesome-go-auth
 * Vanilla JS, no dependencies, ~3KB
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

  let _baseURL = '';
  let _refreshTimer = null;

  function configure(options) {
    if (options && options.baseURL) _baseURL = options.baseURL.replace(/\/$/, '');
  }

  function storeTokens(tokens) {
    if (!tokens) return;
    if (tokens.access_token || tokens.AccessToken) {
      localStorage.setItem(ACCESS_KEY, tokens.access_token || tokens.AccessToken);
    }
    if (tokens.refresh_token || tokens.RefreshToken) {
      localStorage.setItem(REFRESH_KEY, tokens.refresh_token || tokens.RefreshToken);
    }
    scheduleRefresh(tokens);
  }

  function clearTokens() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
  }

  function getAccessToken() {
    return localStorage.getItem(ACCESS_KEY);
  }

  function getRefreshToken() {
    return localStorage.getItem(REFRESH_KEY);
  }

  function isLoggedIn() {
    const tok = getAccessToken();
    if (!tok) return false;
    try {
      const payload = JSON.parse(atob(tok.split('.')[1]));
      return payload.exp ? payload.exp * 1000 > Date.now() : true;
    } catch { return !!tok; }
  }

  function scheduleRefresh(tokens) {
    if (_refreshTimer) clearTimeout(_refreshTimer);
    let expiresIn = tokens.expires_in;
    if (!expiresIn) return;
    // expires_in is in nanoseconds (Go time.Duration)
    const msUntilExpiry = expiresIn / 1e6;
    const refreshIn = Math.max(msUntilExpiry - 30000, 5000); // refresh 30s before expiry
    _refreshTimer = setTimeout(silentRefresh, refreshIn);
  }

  async function silentRefresh() {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return;
    try {
      const resp = await request('POST', '/auth/refresh', { refresh_token: refreshToken });
      storeTokens(resp);
    } catch (e) {
      clearTokens();
      window.dispatchEvent(new CustomEvent('auth:expired'));
    }
  }

  async function request(method, path, body, opts) {
    const url = _baseURL + path;
    const headers = Object.assign({ 'Content-Type': 'application/json' }, (opts || {}).headers);
    const accessToken = getAccessToken();
    if (accessToken && !(opts && opts.skipAuth)) {
      headers['Authorization'] = 'Bearer ' + accessToken;
    }
    const init = { method, headers };
    if (body) init.body = JSON.stringify(body);
    const resp = await fetch(url, init);
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error((data && data.error) || resp.statusText || 'Request failed');
      err.status = resp.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  // ─── Auth API ──────────────────────────────────────────────────────────────

  async function register(email, password, tenantID) {
    const data = await request('POST', '/auth/register', { email, password, tenant_id: tenantID || '' });
    storeTokens(data.tokens);
    window.dispatchEvent(new CustomEvent('auth:register', { detail: data }));
    return data;
  }

  async function login(email, password, tenantID) {
    const data = await request('POST', '/auth/login', { email, password, tenant_id: tenantID || '' });
    storeTokens(data.tokens);
    window.dispatchEvent(new CustomEvent('auth:login', { detail: data }));
    return data;
  }

  async function logout() {
    const refreshToken = getRefreshToken();
    try {
      await request('POST', '/auth/logout', { refresh_token: refreshToken });
    } catch (_) { /* ignore */ }
    clearTokens();
    window.dispatchEvent(new CustomEvent('auth:logout'));
  }

  async function refresh() {
    const refreshToken = getRefreshToken();
    const data = await request('POST', '/auth/refresh', { refresh_token: refreshToken });
    storeTokens(data);
    return data;
  }

  async function me() {
    return request('GET', '/auth/me');
  }

  async function forgotPassword(email, tenantID) {
    return request('POST', '/auth/forgot-password', { email, tenant_id: tenantID || '' });
  }

  async function resetPassword(token, newPassword) {
    return request('POST', '/auth/reset-password', { token, new_password: newPassword });
  }

  async function changePassword(currentPassword, newPassword, userID, tenantID) {
    return request('POST', '/auth/change-password', { current_password: currentPassword, new_password: newPassword, user_id: userID, tenant_id: tenantID });
  }

  async function sendMagicLink(email, tenantID) {
    return request('POST', '/auth/magic-link/send', { email, tenant_id: tenantID || '' });
  }

  async function verifyMagicLink(token) {
    const data = await request('POST', '/auth/magic-link/verify', { token });
    storeTokens(data.tokens);
    window.dispatchEvent(new CustomEvent('auth:login', { detail: data }));
    return data;
  }

  async function sendSMSCode(userID, tenantID) {
    return request('POST', '/auth/sms/send', { user_id: userID, tenant_id: tenantID });
  }

  async function verifySMSCode(userID, tenantID, code) {
    const data = await request('POST', '/auth/sms/verify', { user_id: userID, tenant_id: tenantID, code });
    storeTokens(data.tokens);
    return data;
  }

  async function setupTOTP() {
    return request('POST', '/auth/totp/setup');
  }

  async function verifyTOTPSetup(secret, code) {
    return request('POST', '/auth/totp/setup/verify', { secret, code });
  }

  async function verifyTOTP(userID, tenantID, code) {
    const data = await request('POST', '/auth/totp/verify', { user_id: userID, tenant_id: tenantID, code });
    storeTokens(data.tokens);
    return data;
  }

  async function disableTOTP() {
    return request('POST', '/auth/totp/disable');
  }

  async function sendVerificationEmail() {
    return request('POST', '/auth/email/verify/send');
  }

  async function verifyEmail(token) {
    return request('POST', '/auth/email/verify', { token });
  }

  async function requestEmailChange(newEmail) {
    return request('POST', '/auth/email/change/request', { new_email: newEmail });
  }

  async function confirmEmailChange(token) {
    return request('POST', '/auth/email/change/confirm', { token });
  }

  async function getMetadata() {
    return request('GET', '/auth/metadata');
  }

  async function updateMetadata(metadata) {
    return request('PUT', '/auth/metadata', { metadata });
  }

  async function listSessions() {
    return request('GET', '/auth/sessions');
  }

  async function revokeSession(sessionID) {
    return request('DELETE', '/auth/sessions/' + sessionID);
  }

  // ─── SSE helper ───────────────────────────────────────────────────────────

  function connectSSE(path, onMessage) {
    const token = getAccessToken();
    const url = _baseURL + path + (token ? '?token=' + encodeURIComponent(token) : '');
    const es = new EventSource(url);
    es.addEventListener('message', function (e) {
      try { onMessage(JSON.parse(e.data)); } catch (_) { onMessage(e.data); }
    });
    return es;
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  return {
    configure,
    storeTokens,
    clearTokens,
    getAccessToken,
    getRefreshToken,
    isLoggedIn,
    // Auth
    register,
    login,
    logout,
    refresh,
    me,
    forgotPassword,
    resetPassword,
    changePassword,
    sendMagicLink,
    verifyMagicLink,
    sendSMSCode,
    verifySMSCode,
    setupTOTP,
    verifyTOTPSetup,
    verifyTOTP,
    disableTOTP,
    sendVerificationEmail,
    verifyEmail,
    requestEmailChange,
    confirmEmailChange,
    getMetadata,
    updateMetadata,
    listSessions,
    revokeSession,
    connectSSE,
    // Low-level
    request,
  };
}));

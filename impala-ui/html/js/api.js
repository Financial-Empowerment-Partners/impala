/**
 * API client module for the Impala bridge REST API.
 *
 * Session strategy (cookie-based):
 *  - POST /session/login sets an HttpOnly session cookie (out of reach of
 *    any script, including XSS payloads) and returns a CSRF token.
 *  - The CSRF token lives in memory only (never localStorage) and is sent as
 *    X-CSRF-Token on every state-changing request; it can be re-fetched at
 *    any time from GET /session/me (e.g. after a page reload).
 *  - sessionStorage('impala_user') is a non-authoritative UX cache
 *    (username / is_admin for nav rendering); the cookie is the security
 *    boundary, enforced server-side.
 *
 * Features:
 *  - X-Request-Nonce header on all requests (server-side dedup)
 *  - Error message sanitization (strips HTML/SQL, maps status codes)
 *  - Exponential backoff retry (GET: network + 5xx; mutating: network only)
 *  - One-shot CSRF self-heal: a 403 on a mutation refetches /session/me and
 *    retries once (covers a rotated/lost in-memory token)
 *
 * @module API
 */
var API = (function () {
    /** Base path for all API requests (proxied to impala-bridge by Nginx). */
    var BASE = '/api';

    /** Maximum retry attempts for failed requests. */
    var MAX_RETRIES = 3;
    /** Base delay in milliseconds for exponential backoff. */
    var RETRY_BASE_DELAY = 1000;

    /** sessionStorage key for the non-authoritative user cache. */
    var USER_CACHE_KEY = 'impala_user';

    /** In-memory CSRF token (never persisted). */
    var csrfToken = null;
    /** Cached in-flight /session/me Promise (concurrent callers share it). */
    var csrfPromise = null;

    /**
     * One-time cleanup of the legacy localStorage bearer tokens (the UI used
     * to keep JWTs in localStorage; sessions made that storage obsolete).
     */
    function clearLegacyTokens() {
        try {
            localStorage.removeItem('temporal_token');
            localStorage.removeItem('refresh_token');
        } catch (e) { /* storage unavailable — nothing to clean */ }
    }
    clearLegacyTokens();

    /**
     * Store the session identity returned by /session/login, /session/me or
     * a cookie_mode token exchange: CSRF token in memory, identity in the
     * UX cache.
     * @param {{account_id: string, is_admin: boolean, csrf_token: string}} data
     */
    function setSession(data) {
        if (data && data.csrf_token) {
            csrfToken = data.csrf_token;
        }
        if (data && data.account_id) {
            sessionStorage.setItem(USER_CACHE_KEY, JSON.stringify({
                account_id: data.account_id,
                is_admin: !!data.is_admin
            }));
        }
    }

    /** Clear the in-memory CSRF token and the UX cache (logout/401). */
    function clearSession() {
        csrfToken = null;
        csrfPromise = null;
        sessionStorage.removeItem(USER_CACHE_KEY);
        clearLegacyTokens();
    }

    /**
     * @returns {{account_id: string, is_admin: boolean}|null} The cached
     * session identity (UX only — the server re-checks every request).
     */
    function getCachedUser() {
        try {
            var raw = sessionStorage.getItem(USER_CACHE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    /**
     * Get the CSRF token, fetching it from GET /session/me when the
     * in-memory copy is missing (fresh page load). Rejects when there is no
     * active session.
     * @returns {Promise<string>}
     */
    function getCsrf() {
        if (csrfToken) {
            return Promise.resolve(csrfToken);
        }
        if (csrfPromise) {
            return csrfPromise;
        }
        csrfPromise = fetch(BASE + '/session/me', {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'X-Request-Nonce': generateNonce() }
        }).then(function (res) {
            csrfPromise = null;
            if (!res.ok) {
                throw new Error('Session expired');
            }
            return res.json();
        }).then(function (data) {
            setSession(data);
            if (!csrfToken) {
                throw new Error('Session expired');
            }
            return csrfToken;
        }).catch(function (err) {
            csrfPromise = null;
            throw err;
        });
        return csrfPromise;
    }

    /**
     * Generate a random nonce hex string (request dedup).
     * @returns {string} 32-character hex nonce.
     */
    function generateNonce() {
        var bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + bytes[i].toString(16)).slice(-2);
        }
        return hex;
    }

    /**
     * Build the headers for an authenticated request. Pure — unit-tested.
     * @param {string} method - HTTP method.
     * @param {string|null} csrf - CSRF token (required for non-GET).
     * @param {string} nonce - Request nonce.
     * @returns {Object} Header map.
     */
    function buildHeaders(method, csrf, nonce) {
        var headers = {
            'Content-Type': 'application/json',
            'X-Request-Nonce': nonce
        };
        if (method !== 'GET' && method !== 'HEAD' && csrf) {
            headers['X-CSRF-Token'] = csrf;
        }
        return headers;
    }

    /**
     * Sanitize an error message from the server.
     * Maps known HTTP status codes to user-friendly messages and strips
     * HTML tags and SQL-like keywords from raw messages.
     * @param {number} status - HTTP status code.
     * @param {string} rawMessage - Raw error message from server.
     * @returns {string} Sanitized, user-friendly error message.
     */
    function sanitizeErrorMessage(status, rawMessage) {
        var statusMessages = {
            401: 'Session expired',
            403: 'Permission denied',
            404: 'Not found',
            429: 'Too many requests, please try again later',
            500: 'Server error',
            502: 'Server unavailable',
            503: 'Service temporarily unavailable'
        };

        if (statusMessages[status]) {
            return statusMessages[status];
        }

        if (!rawMessage || typeof rawMessage !== 'string') {
            return 'Request failed (' + status + ')';
        }

        // Strip HTML tags
        var sanitized = rawMessage.replace(/<[^>]*>/g, '');
        // Strip SQL-like content patterns
        sanitized = sanitized.replace(/\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|CREATE|EXEC)\b/gi, '[filtered]');
        // Limit length
        if (sanitized.length > 200) {
            sanitized = sanitized.substring(0, 200) + '...';
        }

        return sanitized || 'Request failed (' + status + ')';
    }

    /**
     * Determine whether a request should be retried.
     * @param {string} method - HTTP method.
     * @param {Error|null} networkError - Network error if fetch itself failed.
     * @param {Response|null} res - Response object if fetch succeeded.
     * @returns {boolean}
     */
    function shouldRetry(method, networkError, res) {
        // Always retry on network errors (for any method)
        if (networkError) return true;
        // For GET, also retry on 5xx
        if (method === 'GET' && res && res.status >= 500) return true;
        // Don't retry 4xx or mutating method 5xx
        return false;
    }

    /**
     * Delay execution for a given duration.
     * @param {number} ms - Milliseconds to wait.
     * @returns {Promise<void>}
     */
    function delay(ms) {
        return new Promise(function (resolve) {
            setTimeout(resolve, ms);
        });
    }

    /**
     * Make an authenticated HTTP request to the API with retry logic.
     * The session cookie rides along automatically (same-origin); mutations
     * additionally carry X-CSRF-Token. Handles 401 redirects, a one-shot
     * CSRF self-heal on 403, and exponential backoff retries.
     * @param {string} method - HTTP method (GET, POST, PUT, DELETE).
     * @param {string} path   - API path (e.g. '/account').
     * @param {Object} [body] - Request body (will be JSON-serialized).
     * @returns {Promise<Response>} The fetch Response object.
     */
    function request(method, path, body) {
        var needsCsrf = method !== 'GET' && method !== 'HEAD';
        var csrfHealed = false;

        function obtainCsrf() {
            return needsCsrf ? getCsrf() : Promise.resolve(null);
        }

        return obtainCsrf().then(function (csrf) {
            var attempt = 0;

            function doFetch(currentCsrf) {
                var opts = {
                    method: method,
                    credentials: 'same-origin',
                    headers: buildHeaders(method, currentCsrf, generateNonce())
                };
                if (body !== undefined) {
                    opts.body = JSON.stringify(body);
                }

                return fetch(BASE + path, opts).then(function (res) {
                    if (res.status === 401) {
                        clearSession();
                        window.location.href = 'index.html';
                        return Promise.reject(new Error('Unauthorized'));
                    }

                    // Stale in-memory CSRF token (e.g. another tab re-logged
                    // in): refetch it once and retry the request.
                    if (res.status === 403 && needsCsrf && !csrfHealed) {
                        csrfHealed = true;
                        csrfToken = null;
                        return getCsrf().then(doFetch);
                    }

                    if (attempt < MAX_RETRIES && shouldRetry(method, null, res)) {
                        attempt++;
                        var waitMs = RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
                        return delay(waitMs).then(function () {
                            return doFetch(currentCsrf);
                        });
                    }

                    return res;
                }).catch(function (err) {
                    // Network error (fetch itself failed)
                    if (err.message === 'Unauthorized') throw err;

                    if (attempt < MAX_RETRIES && shouldRetry(method, err, null)) {
                        attempt++;
                        var waitMs = RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
                        return delay(waitMs).then(function () {
                            return doFetch(currentCsrf);
                        });
                    }
                    throw err;
                });
            }

            return doFetch(csrf);
        });
    }

    /**
     * Parse a Response as JSON if the Content-Type indicates JSON,
     * otherwise return the body as text. Throws on non-OK status with
     * sanitized error messages.
     * @param {Response} res - The fetch Response.
     * @returns {Promise<Object|string>} Parsed response body.
     */
    function jsonOrError(res) {
        if (!res.ok) {
            var status = res.status;
            return res.text().then(function (t) {
                throw new Error(sanitizeErrorMessage(status, t));
            });
        }
        // A successful API call counts as session activity.
        if (typeof SessionTimer !== 'undefined') {
            SessionTimer.reset();
        }
        var ct = res.headers.get('content-type') || '';
        if (ct.indexOf('application/json') !== -1) {
            return res.json();
        }
        return res.text();
    }

    /**
     * Set a button to a loading state (disabled + spinner) or restore it.
     * @param {HTMLButtonElement} btn - The button element.
     * @param {boolean} loading - True to show loading, false to restore.
     */
    function setButtonLoading(btn, loading) {
        if (!btn) return;
        if (loading) {
            if (!btn.hasAttribute('data-original-text')) {
                btn.setAttribute('data-original-text', btn.textContent);
            }
            btn.disabled = true;
            btn.classList.add('btn-loading');
        } else {
            btn.disabled = false;
            btn.classList.remove('btn-loading');
            var orig = btn.getAttribute('data-original-text');
            if (orig) {
                btn.textContent = orig;
                btn.removeAttribute('data-original-text');
            }
        }
    }

    return {
        BASE: BASE,
        setSession: setSession,
        clearSession: clearSession,
        getCachedUser: getCachedUser,
        buildHeaders: buildHeaders,
        sanitizeErrorMessage: sanitizeErrorMessage,
        setButtonLoading: setButtonLoading,

        /** Authenticated GET request. Returns parsed JSON or text. */
        get: function (path) {
            return request('GET', path).then(jsonOrError);
        },
        /** Authenticated POST request. Returns parsed JSON or text. */
        post: function (path, body) {
            return request('POST', path, body).then(jsonOrError);
        },
        /** Authenticated PUT request. Returns parsed JSON or text. */
        put: function (path, body) {
            return request('PUT', path, body).then(jsonOrError);
        },
        /** Authenticated DELETE request. Returns parsed JSON or text. */
        del: function (path) {
            return request('DELETE', path).then(jsonOrError);
        },

        /**
         * Unauthenticated POST request for the login flow.
         * No CSRF header (the endpoints are body-credentialed); cookies are
         * included so /session/login's Set-Cookie applies.
         * @param {string} path - API path.
         * @param {Object} body - Request body.
         * @returns {Promise<Response>} Raw fetch Response.
         */
        rawPost: function (path, body) {
            return fetch(BASE + path, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Request-Nonce': generateNonce()
                },
                body: JSON.stringify(body)
            });
        }
    };
})();

/**
 * API client module for the Impala bridge REST API.
 *
 * Handles JWT token storage, automatic token refresh, and authenticated
 * HTTP requests. All methods return Promises. On 401 responses, tokens
 * are cleared and the user is redirected to the login page.
 *
 * Token strategy:
 *  - refresh_token (14-day): obtained via username+password
 *  - temporal_token (1-hour): obtained from refresh_token, used for API calls
 *
 * Features:
 *  - X-Request-Nonce header on all requests (server-side dedup)
 *  - Error message sanitization (strips HTML/SQL, maps status codes)
 *  - Exponential backoff retry (GET: network + 5xx; mutating: network only)
 *
 * Authentication is bearer-token only: every mutation carries an Authorization
 * header, so no ambient credential is attached and these requests are not
 * CSRF-reachable. There is deliberately no X-CSRF-Token handling here — the
 * bridge enforces CSRF on its cookie-session path, which this client does not
 * use (`rawPost` sends cookies but is only used for body-credentialed login
 * endpoints). See test/api-csrf.test.js for the cookie-session surface that
 * would need to exist first.
 *
 * @module API
 */
var API = (function () {
    /** Maximum retry attempts for failed requests. */
    var MAX_RETRIES = 3;
    /** Base delay in milliseconds for exponential backoff. */
    var RETRY_BASE_DELAY = 1000;

    /** @returns {Object|null} The runtime network config, if loaded. */
    function getConfig() {
        return (typeof window !== 'undefined' && window.IMPALA_CONFIG) ? window.IMPALA_CONFIG : null;
    }

    /**
     * The active network key (e.g. 'testnet'), derived from the persisted
     * selection in localStorage and validated against the runtime config.
     * @returns {string|null}
     */
    function currentNetworkKey() {
        var stored = null;
        try { stored = localStorage.getItem('impala_network'); } catch (e) { /* ignore */ }
        var cfg = getConfig();
        if (typeof NetConfig !== 'undefined') {
            return NetConfig.resolveKey(cfg, stored);
        }
        return stored || (cfg && cfg.default) || null;
    }

    /**
     * Base path for all API requests on the active network (proxied to the
     * matching bridge by Nginx). Resolved dynamically so a network switch takes
     * effect without reloading api.js.
     * @returns {string}
     */
    function base() {
        var cfg = getConfig();
        if (typeof NetConfig !== 'undefined') {
            return NetConfig.resolveBase(cfg, currentNetworkKey());
        }
        return '/api';
    }

    /**
     * Build the per-network localStorage key for a token name. JWTs are not
     * portable across bridges, so each network's tokens live under their own key
     * (e.g. 'temporal_token::mainnet').
     * @param {string} name
     * @returns {string}
     */
    function tokenStorageKey(name) {
        var netKey = currentNetworkKey();
        if (typeof NetConfig !== 'undefined' && NetConfig.tokenKey) {
            return NetConfig.tokenKey(name, netKey);
        }
        return netKey ? name + '::' + netKey : name;
    }

    /** @returns {string|null} The stored temporal (short-lived) JWT token. */
    function getTemporalToken() {
        return localStorage.getItem(tokenStorageKey('temporal_token'));
    }

    /** @returns {string|null} The stored refresh (long-lived) JWT token. */
    function getRefreshToken() {
        return localStorage.getItem(tokenStorageKey('refresh_token'));
    }

    /**
     * Store JWT tokens for the active network in localStorage.
     * @param {string|null} temporal - Temporal token (1-hour), or null to skip.
     * @param {string|null} refresh  - Refresh token (14-day), or null to skip.
     */
    function setTokens(temporal, refresh) {
        if (temporal) localStorage.setItem(tokenStorageKey('temporal_token'), temporal);
        if (refresh) localStorage.setItem(tokenStorageKey('refresh_token'), refresh);
    }

    /** Remove the active network's stored tokens from localStorage. */
    function clearTokens() {
        localStorage.removeItem(tokenStorageKey('temporal_token'));
        localStorage.removeItem(tokenStorageKey('refresh_token'));
    }

    /**
     * Decode a JWT token's payload without signature verification.
     * @param {string} token - The JWT string.
     * @returns {Object|null} Decoded payload, or null on parse failure.
     */
    function parseJwt(token) {
        try {
            if (!token || typeof token !== 'string') return null;
            var parts = token.split('.');
            if (parts.length !== 3) return null;
            var payload = parts[1];
            if (!payload) return null;
            return JSON.parse(atob(payload));
        } catch (e) {
            return null;
        }
    }

    /**
     * True when a JWT is expired or unreadable (fail closed). A 60-second
     * early-expiry skew keeps in-flight requests off a token that would die
     * before the server sees it.
     * @param {string} token - Encoded JWT.
     * @returns {boolean}
     */
    function isTokenExpired(token) {
        var payload = parseJwt(token);
        if (!payload || typeof payload.exp !== 'number') {
            return true;
        }
        return payload.exp * 1000 <= Date.now() + 60 * 1000;
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
     * Fallback sanitizer for NON-enveloped error bodies (see extractErrorMessage,
     * which prefers a structured `{error:{message}}` body and is what callers hit
     * first). Maps known HTTP status codes to user-friendly messages and strips
     * HTML tags + SQL-like keywords from raw messages (leak-defense for
     * unexpected, non-API responses such as a proxy HTML error page).
     * @param {number} status - HTTP status code.
     * @param {string} rawMessage - Raw error message from server.
     * @returns {string} Sanitized, user-friendly error message.
     */
    function sanitizeErrorMessage(status, rawMessage) {
        var statusMessages = {
            401: 'Session expired',
            403: 'Permission denied',
            404: 'Not found',
            409: 'Conflict',
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
     * Strip HTML tags and cap length, WITHOUT the SQL-keyword replacement.
     * Used for trusted, API-shaped envelope messages (which legitimately contain
     * words like "delete"/"role"), so guard messages are not mangled. The result
     * is only ever rendered via textContent or an escapeHtml() sink, so tag
     * stripping is belt-and-suspenders rather than the sole XSS defense.
     * @param {string} message
     * @returns {string}
     */
    function stripAndTruncate(message) {
        var sanitized = String(message).replace(/<[^>]*>/g, '');
        if (sanitized.length > 200) {
            sanitized = sanitized.substring(0, 200) + '...';
        }
        return sanitized || 'Request failed';
    }

    /**
     * Extract the `message` from a bridge error envelope `{error:{message}}`.
     * @param {string} rawBody - Raw response body text.
     * @returns {string|null} The envelope message, or null if not enveloped.
     */
    function parseEnvelopeMessage(rawBody) {
        if (!rawBody || typeof rawBody !== 'string') return null;
        try {
            var parsed = JSON.parse(rawBody);
            if (parsed && parsed.error && typeof parsed.error.message === 'string') {
                return parsed.error.message;
            }
        } catch (e) {
            // Not JSON — fall through to the raw-body fallback.
        }
        return null;
    }

    /**
     * Turn an error response (status + raw body) into a display message.
     * Prefers the bridge's structured `{error:{message}}` envelope (lightly
     * sanitized, NOT SQL-filtered) so guard messages surface cleanly for every
     * status; otherwise falls back to the status map + raw-body sanitization.
     * @param {number} status
     * @param {string} rawBody
     * @returns {string}
     */
    function extractErrorMessage(status, rawBody) {
        var enveloped = parseEnvelopeMessage(rawBody);
        if (enveloped !== null) {
            return stripAndTruncate(enveloped);
        }
        return sanitizeErrorMessage(status, rawBody);
    }

    /** Cached in-flight refresh Promise to prevent concurrent refresh requests. */
    var refreshPromise = null;

    /**
     * Use the stored refresh token to obtain a new temporal token.
     * Clears all tokens and rejects if the refresh token is missing or expired.
     * Concurrent callers share a single in-flight request.
     * @returns {Promise<string>} Resolves with the new temporal token.
     */
    function refreshTemporalToken() {
        if (refreshPromise) {
            return refreshPromise;
        }

        var refresh = getRefreshToken();
        if (!refresh || isTokenExpired(refresh)) {
            clearTokens();
            return Promise.reject(new Error('Session expired'));
        }

        refreshPromise = fetch(base() + '/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Request-Nonce': generateNonce()
            },
            body: JSON.stringify({ refresh_token: refresh })
        }).then(function (res) {
            if (!res.ok) {
                clearTokens();
                throw new Error('Token refresh failed');
            }
            return res.json();
        }).then(function (data) {
            refreshPromise = null;
            if (data.temporal_token) {
                setTokens(data.temporal_token, null);
                return data.temporal_token;
            }
            throw new Error('No temporal token in response');
        }).catch(function (err) {
            refreshPromise = null;
            throw err;
        });

        return refreshPromise;
    }

    /**
     * Get a valid temporal token, refreshing if the current one has expired.
     * @returns {Promise<string>} Resolves with a non-expired temporal token.
     */
    function getValidToken() {
        var token = getTemporalToken();
        if (token && !isTokenExpired(token)) {
            return Promise.resolve(token);
        }
        return refreshTemporalToken();
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
     * Attaches a bearer temporal token (refreshed up front when expired, and
     * self-healed once on a 401 — e.g. a token revoked from another tab),
     * with exponential backoff retries for idempotent requests. Redirects to
     * the login page when no session can be established.
     * @param {string} method - HTTP method (GET, POST, PUT, DELETE).
     * @param {string} path   - API path (e.g. '/account').
     * @param {Object} [body] - Request body (will be JSON-serialized).
     * @returns {Promise<Response>} The fetch Response object.
     */
    function request(method, path, body) {
        var authHealed = false;

        return getValidToken().then(function (token) {
            var attempt = 0;

            function doFetch(currentToken) {
                var opts = {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + currentToken,
                        'X-Request-Nonce': generateNonce()
                    }
                };
                if (body !== undefined) {
                    opts.body = JSON.stringify(body);
                }

                return fetch(base() + path, opts).then(function (res) {
                    if (res.status === 401) {
                        // Stale temporal token (revoked, or rotated by another
                        // tab): refresh once and retry; a second 401 means the
                        // session is over.
                        if (!authHealed) {
                            authHealed = true;
                            return refreshTemporalToken().then(doFetch).catch(function () {
                                clearTokens();
                                window.location.href = 'index.html';
                                return Promise.reject(new Error('Unauthorized'));
                            });
                        }
                        clearTokens();
                        window.location.href = 'index.html';
                        return Promise.reject(new Error('Unauthorized'));
                    }

                    if (attempt < MAX_RETRIES && shouldRetry(method, null, res)) {
                        attempt++;
                        var waitMs = RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
                        return delay(waitMs).then(function () {
                            return doFetch(currentToken);
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
                            return doFetch(currentToken);
                        });
                    }
                    throw err;
                });
            }

            return doFetch(token);
        }).catch(function (err) {
            // No refresh token / refresh failed: bounce to login.
            if (err && err.message === 'Session expired') {
                window.location.href = 'index.html';
            }
            throw err;
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
                var err = new Error(extractErrorMessage(status, t));
                err.status = status;
                throw err;
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
        /** Active network's API base path (dynamic getter, e.g. '/api/testnet'). */
        get BASE() { return base(); },
        currentNetworkKey: currentNetworkKey,
        getTemporalToken: getTemporalToken,
        getRefreshToken: getRefreshToken,
        setTokens: setTokens,
        clearTokens: clearTokens,
        parseJwt: parseJwt,
        isTokenExpired: isTokenExpired,
        sanitizeErrorMessage: sanitizeErrorMessage,
        extractErrorMessage: extractErrorMessage,
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
            return fetch(base() + path, {
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

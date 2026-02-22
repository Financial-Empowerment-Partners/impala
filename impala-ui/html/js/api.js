/**
 * API client module for the Impala bridge REST API.
 *
 * Handles JWT token storage, automatic token refresh, and authenticated
 * HTTP requests. All methods return Promises. On 401 responses, tokens
 * are cleared and the user is redirected to the login page.
 *
 * Token strategy:
 *  - refresh_token (30-day): obtained via username+password
 *  - temporal_token (1-hour): obtained from refresh_token, used for API calls
 *
 * Features:
 *  - X-Request-Nonce header on all requests (CSRF mitigation)
 *  - Error message sanitization (strips HTML/SQL, maps status codes)
 *  - Exponential backoff retry (GET: network + 5xx; mutating: network only)
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

    /** @returns {string|null} The stored temporal (short-lived) JWT token. */
    function getTemporalToken() {
        return localStorage.getItem('temporal_token');
    }

    /** @returns {string|null} The stored refresh (long-lived) JWT token. */
    function getRefreshToken() {
        return localStorage.getItem('refresh_token');
    }

    /**
     * Store JWT tokens in localStorage.
     * @param {string|null} temporal - Temporal token (1-hour), or null to skip.
     * @param {string|null} refresh  - Refresh token (30-day), or null to skip.
     */
    function setTokens(temporal, refresh) {
        if (temporal) localStorage.setItem('temporal_token', temporal);
        if (refresh) localStorage.setItem('refresh_token', refresh);
    }

    /** Remove all stored tokens from localStorage. */
    function clearTokens() {
        localStorage.removeItem('temporal_token');
        localStorage.removeItem('refresh_token');
    }

    /**
     * Decode a JWT token's payload without signature verification.
     * @param {string} token - The JWT string.
     * @returns {Object|null} Decoded payload, or null on parse failure.
     */
    function parseJwt(token) {
        try {
            var payload = token.split('.')[1];
            return JSON.parse(atob(payload));
        } catch (e) {
            return null;
        }
    }

    /**
     * Check whether a JWT token has expired based on its `exp` claim.
     * @param {string} token - The JWT string.
     * @returns {boolean} True if expired or unparseable.
     */
    function isTokenExpired(token) {
        var payload = parseJwt(token);
        if (!payload || !payload.exp) return true;
        return Date.now() >= payload.exp * 1000;
    }

    /**
     * Generate a random nonce hex string for CSRF mitigation.
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

        refreshPromise = fetch(BASE + '/token', {
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
     * Automatically injects the Authorization and X-Request-Nonce headers.
     * Handles 401 redirects and exponential backoff retries.
     * @param {string} method - HTTP method (GET, POST, PUT, DELETE).
     * @param {string} path   - API path (e.g. '/account').
     * @param {Object} [body] - Request body (will be JSON-serialized).
     * @returns {Promise<Response>} The fetch Response object.
     */
    function request(method, path, body) {
        return getValidToken().then(function (token) {
            var attempt = 0;

            function doFetch() {
                var opts = {
                    method: method,
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json',
                        'X-Request-Nonce': generateNonce()
                    }
                };
                if (body !== undefined) {
                    opts.body = JSON.stringify(body);
                }

                return fetch(BASE + path, opts).then(function (res) {
                    if (res.status === 401) {
                        clearTokens();
                        window.location.href = 'index.html';
                        return Promise.reject(new Error('Unauthorized'));
                    }

                    if (attempt < MAX_RETRIES && shouldRetry(method, null, res)) {
                        attempt++;
                        var waitMs = RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
                        return delay(waitMs).then(doFetch);
                    }

                    return res;
                }).catch(function (err) {
                    // Network error (fetch itself failed)
                    if (err.message === 'Unauthorized') throw err;

                    if (attempt < MAX_RETRIES && shouldRetry(method, err, null)) {
                        attempt++;
                        var waitMs = RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
                        return delay(waitMs).then(doFetch);
                    }
                    throw err;
                });
            }

            return doFetch();
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
        setTokens: setTokens,
        clearTokens: clearTokens,
        parseJwt: parseJwt,
        isTokenExpired: isTokenExpired,
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
         * Does not inject Authorization header or handle 401 redirects.
         * Includes X-Request-Nonce header for CSRF mitigation.
         * @param {string} path - API path.
         * @param {Object} body - Request body.
         * @returns {Promise<Response>} Raw fetch Response.
         */
        rawPost: function (path, body) {
            return fetch(BASE + path, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Request-Nonce': generateNonce()
                },
                body: JSON.stringify(body)
            });
        }
    };
})();

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
 * @module API
 */
var API = (function () {
    /** Base path for all API requests (proxied to impala-bridge by Nginx). */
    var BASE = '/api';

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
            headers: { 'Content-Type': 'application/json' },
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
     * Make an authenticated HTTP request to the API.
     * Automatically injects the Authorization header and handles 401 redirects.
     * @param {string} method - HTTP method (GET, POST, PUT, DELETE).
     * @param {string} path   - API path (e.g. '/account').
     * @param {Object} [body] - Request body (will be JSON-serialized).
     * @returns {Promise<Response>} The fetch Response object.
     */
    function request(method, path, body) {
        return getValidToken().then(function (token) {
            var opts = {
                method: method,
                headers: {
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                }
            };
            if (body !== undefined) {
                opts.body = JSON.stringify(body);
            }
            return fetch(BASE + path, opts);
        }).then(function (res) {
            if (res.status === 401) {
                clearTokens();
                window.location.href = 'index.html';
                return Promise.reject(new Error('Unauthorized'));
            }
            return res;
        });
    }

    /**
     * Parse a Response as JSON if the Content-Type indicates JSON,
     * otherwise return the body as text. Throws on non-OK status.
     * @param {Response} res - The fetch Response.
     * @returns {Promise<Object|string>} Parsed response body.
     */
    function jsonOrError(res) {
        if (!res.ok) {
            return res.text().then(function (t) {
                throw new Error(t || 'Request failed (' + res.status + ')');
            });
        }
        var ct = res.headers.get('content-type') || '';
        if (ct.indexOf('application/json') !== -1) {
            return res.json();
        }
        return res.text();
    }

    return {
        BASE: BASE,
        setTokens: setTokens,
        clearTokens: clearTokens,
        parseJwt: parseJwt,
        isTokenExpired: isTokenExpired,

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
         * @param {string} path - API path.
         * @param {Object} body - Request body.
         * @returns {Promise<Response>} Raw fetch Response.
         */
        rawPost: function (path, body) {
            return fetch(BASE + path, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
        }
    };
})();

/**
 * Authentication module handling login, logout, and session state.
 *
 * Login is a 2-step process:
 *  1. POST /authenticate — validate credentials and register if first login
 *  2. POST /token (username+password) — obtain the 14-day refresh token
 *     (the response also carries the 1-hour temporal token, so no extra
 *     refresh round trip is needed)
 *
 * Tokens are namespaced per Stellar network (see api.js / net-config.js), so all
 * token access goes through the API module rather than hardcoded storage keys.
 * Authorization is server-driven: the role comes from the token's `role` claim.
 *
 * @module Auth
 */
var Auth = (function () {
    /**
     * Check whether the user has an active (non-expired) session on the active
     * network.
     * @returns {boolean} True if a valid refresh token exists.
     */
    function isLoggedIn() {
        var refresh = API.getRefreshToken();
        if (!refresh) return false;
        return !API.isTokenExpired(refresh);
    }

    /**
     * Get the logged-in username (JWT `sub`) from the stored tokens.
     * @returns {string|null}
     */
    function getUsername() {
        var token = API.getRefreshToken() || API.getTemporalToken();
        if (!token) return null;
        var payload = API.parseJwt(token);
        return payload ? (payload.sub || payload.username || null) : null;
    }

    /**
     * Authenticate with the backend and store the issued token pair for the
     * active network.
     * @param {string} accountId - The user's Payala account ID.
     * @param {string} password  - The user's password (min 8 characters).
     * @returns {Promise<{success: boolean, username: string}>}
     */
    function login(accountId, password) {
        // Step 1: authenticate (register if new, verify if existing)
        return API.rawPost('/authenticate', {
            account_id: accountId,
            password: password
        }).then(function (res) {
            if (!res.ok) {
                return res.text().then(function (t) {
                    throw new Error(t || 'Authentication failed');
                });
            }
            return res.json();
        }).then(function () {
            // Step 2: obtain the refresh + temporal token pair
            return API.rawPost('/token', {
                username: accountId,
                password: password
            });
        }).then(function (res) {
            if (!res.ok) {
                return res.text().then(function (t) {
                    throw new Error(t || 'Login failed');
                });
            }
            return res.json();
        }).then(function (data) {
            if (!data.success || !data.refresh_token) {
                throw new Error(data.message || 'Login failed');
            }
            API.setTokens(data.temporal_token || null, data.refresh_token);

            // Authorization is server-driven: the role rides in the token's claim.
            return { success: true, username: accountId };
        });
    }

    /**
     * Revoke the presented token server-side, clear the active network's
     * tokens, and redirect to the login page. Local cleanup + redirect happen
     * even if the server call fails (best effort — the tokens still age out).
     */
    function logout() {
        if (typeof SessionTimer !== 'undefined') {
            SessionTimer.stop();
        }
        return API.post('/logout').catch(function () {
            // Network/permission failure: still drop local state below.
        }).then(function () {
            API.clearTokens();
            window.location.href = 'index.html';
        });
    }

    /**
     * Redirect to login if the user is not authenticated.
     * @returns {boolean} True if authenticated, false if redirecting.
     */
    function requireAuth() {
        if (!isLoggedIn()) {
            window.location.href = 'index.html';
            return false;
        }
        return true;
    }

    return {
        isLoggedIn: isLoggedIn,
        getUsername: getUsername,
        login: login,
        logout: logout,
        requireAuth: requireAuth
    };
})();

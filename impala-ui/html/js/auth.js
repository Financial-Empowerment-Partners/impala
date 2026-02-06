/**
 * Authentication module handling login, logout, and session state.
 *
 * Login is a 3-step process:
 *  1. POST /authenticate — validate credentials and register if first login
 *  2. POST /token (username+password) — obtain a 30-day refresh token
 *  3. POST /token (refresh_token) — obtain a 1-hour temporal token
 *
 * The first user to log in is automatically bootstrapped as admin via Roles.bootstrap().
 *
 * @module Auth
 */
var Auth = (function () {
    /**
     * Check whether the user has an active (non-expired) session.
     * @returns {boolean} True if a valid refresh token exists.
     */
    function isLoggedIn() {
        var refresh = localStorage.getItem('refresh_token');
        if (!refresh) return false;
        return !API.isTokenExpired(refresh);
    }

    /**
     * Extract the username from the stored JWT token's `sub` claim.
     * @returns {string|null} The username, or null if no token exists.
     */
    function getUsername() {
        var token = localStorage.getItem('refresh_token') || localStorage.getItem('temporal_token');
        if (!token) return null;
        var payload = API.parseJwt(token);
        return payload ? (payload.sub || payload.username || null) : null;
    }

    /**
     * Get the expiration time of the current temporal token.
     * @returns {Date|null} Expiry date, or null if no temporal token exists.
     */
    function getTokenExpiry() {
        var token = localStorage.getItem('temporal_token');
        if (!token) return null;
        var payload = API.parseJwt(token);
        if (!payload || !payload.exp) return null;
        return new Date(payload.exp * 1000);
    }

    /**
     * Authenticate with the backend and obtain JWT tokens.
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
            // Step 2: obtain long-lived refresh token
            return API.rawPost('/token', {
                username: accountId,
                password: password
            });
        }).then(function (res) {
            if (!res.ok) {
                return res.text().then(function (t) {
                    throw new Error(t || 'Token request failed');
                });
            }
            return res.json();
        }).then(function (data) {
            if (!data.refresh_token) throw new Error('No refresh token received');
            API.setTokens(null, data.refresh_token);

            // Step 3: exchange refresh token for short-lived temporal token
            return API.rawPost('/token', {
                refresh_token: data.refresh_token
            });
        }).then(function (res) {
            if (!res.ok) {
                return res.text().then(function (t) {
                    throw new Error(t || 'Temporal token request failed');
                });
            }
            return res.json();
        }).then(function (data) {
            if (!data.temporal_token) throw new Error('No temporal token received');
            API.setTokens(data.temporal_token, null);

            // Bootstrap roles — first user becomes admin
            Roles.bootstrap(accountId);

            return { success: true, username: accountId };
        });
    }

    /** Clear tokens and redirect to the login page. */
    function logout() {
        API.clearTokens();
        window.location.href = 'index.html';
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
        getTokenExpiry: getTokenExpiry,
        login: login,
        logout: logout,
        requireAuth: requireAuth
    };
})();

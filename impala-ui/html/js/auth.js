/**
 * Authentication module handling login, logout, and session state.
 *
 * Login is a 2-step process:
 *  1. POST /authenticate — validate credentials and register if first login
 *  2. POST /session/login — establish an HttpOnly cookie session; the
 *     response carries the CSRF token (kept in memory by API) and the
 *     session identity (cached in sessionStorage for nav rendering)
 *
 * The cookie is the security boundary: it is HttpOnly (invisible to script)
 * and validated server-side on every request. No tokens are kept in
 * localStorage.
 *
 * The first user to log in is automatically bootstrapped as admin via
 * Roles.bootstrap().
 *
 * @module Auth
 */
var Auth = (function () {
    /**
     * Check whether the user has an active session, per the local UX cache.
     * Non-authoritative — the server is the actual gate (a stale cache just
     * means one redirected request).
     * @returns {boolean}
     */
    function isLoggedIn() {
        return !!API.getCachedUser();
    }

    /**
     * Get the logged-in username from the session cache.
     * @returns {string|null}
     */
    function getUsername() {
        var user = API.getCachedUser();
        return user ? user.account_id : null;
    }

    /**
     * Whether the session belongs to a bridge admin (from the server-issued
     * session identity; display only — the server enforces it per request).
     * @returns {boolean}
     */
    function isAdmin() {
        var user = API.getCachedUser();
        return !!(user && user.is_admin);
    }

    /**
     * Authenticate with the backend and establish a cookie session.
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
            // Step 2: establish the cookie session (sets the HttpOnly
            // cookie; the JSON body carries the CSRF token + identity)
            return API.rawPost('/session/login', {
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
            if (!data.success) throw new Error(data.message || 'Login failed');
            API.setSession(data);

            // Bootstrap roles — first user becomes admin
            Roles.bootstrap(accountId);

            return { success: true, username: accountId };
        });
    }

    /**
     * Destroy the server-side session, clear local caches, and redirect to
     * the login page. Local cleanup + redirect happen even if the server
     * call fails (best effort — the cookie still dies with the session TTL).
     */
    function logout() {
        if (typeof SessionTimer !== 'undefined') {
            SessionTimer.stop();
        }
        return API.post('/session/logout').catch(function () {
            // Network/permission failure: still drop local state below.
        }).then(function () {
            API.clearSession();
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
        isAdmin: isAdmin,
        login: login,
        logout: logout,
        requireAuth: requireAuth
    };
})();

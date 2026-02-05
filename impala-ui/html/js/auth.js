var Auth = (function () {
    function isLoggedIn() {
        var refresh = localStorage.getItem('refresh_token');
        if (!refresh) return false;
        return !API.isTokenExpired(refresh);
    }

    function getUsername() {
        var token = localStorage.getItem('refresh_token') || localStorage.getItem('temporal_token');
        if (!token) return null;
        var payload = API.parseJwt(token);
        return payload ? (payload.sub || payload.username || null) : null;
    }

    function getTokenExpiry() {
        var token = localStorage.getItem('temporal_token');
        if (!token) return null;
        var payload = API.parseJwt(token);
        if (!payload || !payload.exp) return null;
        return new Date(payload.exp * 1000);
    }

    function login(accountId, password) {
        // Step 1: authenticate
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
            // Step 2: get refresh token
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

            // Step 3: get temporal token
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

            // Bootstrap roles for first user
            Roles.bootstrap(accountId);

            return { success: true, username: accountId };
        });
    }

    function logout() {
        API.clearTokens();
        window.location.href = 'index.html';
    }

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

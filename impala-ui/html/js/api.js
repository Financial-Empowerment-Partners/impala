var API = (function () {
    var BASE = '/api';

    function getTemporalToken() {
        return localStorage.getItem('temporal_token');
    }

    function getRefreshToken() {
        return localStorage.getItem('refresh_token');
    }

    function setTokens(temporal, refresh) {
        if (temporal) localStorage.setItem('temporal_token', temporal);
        if (refresh) localStorage.setItem('refresh_token', refresh);
    }

    function clearTokens() {
        localStorage.removeItem('temporal_token');
        localStorage.removeItem('refresh_token');
    }

    function parseJwt(token) {
        try {
            var payload = token.split('.')[1];
            return JSON.parse(atob(payload));
        } catch (e) {
            return null;
        }
    }

    function isTokenExpired(token) {
        var payload = parseJwt(token);
        if (!payload || !payload.exp) return true;
        return Date.now() >= payload.exp * 1000;
    }

    function refreshTemporalToken() {
        var refresh = getRefreshToken();
        if (!refresh || isTokenExpired(refresh)) {
            clearTokens();
            return Promise.reject(new Error('Session expired'));
        }

        return fetch(BASE + '/token', {
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
            if (data.temporal_token) {
                setTokens(data.temporal_token, null);
                return data.temporal_token;
            }
            throw new Error('No temporal token in response');
        });
    }

    function getValidToken() {
        var token = getTemporalToken();
        if (token && !isTokenExpired(token)) {
            return Promise.resolve(token);
        }
        return refreshTemporalToken();
    }

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

        get: function (path) {
            return request('GET', path).then(jsonOrError);
        },
        post: function (path, body) {
            return request('POST', path, body).then(jsonOrError);
        },
        put: function (path, body) {
            return request('PUT', path, body).then(jsonOrError);
        },
        del: function (path) {
            return request('DELETE', path).then(jsonOrError);
        },

        // Unauthenticated requests for login flow
        rawPost: function (path, body) {
            return fetch(BASE + path, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
        }
    };
})();

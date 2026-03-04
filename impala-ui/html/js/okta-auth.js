/**
 * Okta OAuth 2.0 authentication module.
 *
 * Handles Authorization Code + PKCE flow for browser-based Okta login.
 * Communicates with the bridge's `/api/auth/okta` and `/api/auth/okta/config`
 * endpoints for token exchange and configuration discovery.
 *
 * @module OktaAuth
 */
var OktaAuth = (function () {
    var config = null;

    /**
     * Initialize Okta authentication.
     * Fetches the Okta configuration from the bridge and shows/hides the
     * Okta login button based on whether Okta is enabled.
     */
    function init() {
        var oktaBtn = document.getElementById('okta-login-btn');
        var oktaDivider = document.getElementById('okta-divider');

        fetch(API.BASE + '/auth/okta/config')
            .then(function (res) {
                if (!res.ok) throw new Error('Failed to fetch Okta config');
                return res.json();
            })
            .then(function (data) {
                config = data;
                if (data.enabled && oktaBtn) {
                    oktaBtn.classList.remove('hidden');
                    if (oktaDivider) oktaDivider.classList.remove('hidden');
                    oktaBtn.addEventListener('click', function () {
                        startLogin();
                    });
                }
            })
            .catch(function () {
                // Okta not available — keep button hidden
            });
    }

    /**
     * Generate a cryptographically random string for PKCE code verifier.
     * @returns {string} URL-safe base64-encoded random string.
     */
    function generateCodeVerifier() {
        var bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        return base64UrlEncode(bytes);
    }

    /**
     * Generate a PKCE code challenge from a code verifier using SHA-256.
     * @param {string} verifier - The code verifier string.
     * @returns {Promise<string>} URL-safe base64-encoded SHA-256 hash.
     */
    function generateCodeChallenge(verifier) {
        var encoder = new TextEncoder();
        var data = encoder.encode(verifier);
        return crypto.subtle.digest('SHA-256', data).then(function (hash) {
            return base64UrlEncode(new Uint8Array(hash));
        });
    }

    /**
     * Base64url-encode a Uint8Array (no padding).
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    function base64UrlEncode(bytes) {
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    /**
     * Start the Okta login flow.
     * Generates PKCE verifier/challenge, stores state in sessionStorage,
     * and redirects the user to Okta's authorization endpoint.
     */
    function startLogin() {
        if (!config || !config.enabled) return;

        var codeVerifier = generateCodeVerifier();
        var state = generateCodeVerifier(); // random state for CSRF protection

        generateCodeChallenge(codeVerifier).then(function (codeChallenge) {
            sessionStorage.setItem('okta_code_verifier', codeVerifier);
            sessionStorage.setItem('okta_state', state);

            var params = [
                'client_id=' + encodeURIComponent(config.client_id),
                'redirect_uri=' + encodeURIComponent(window.location.origin + '/okta-callback.html'),
                'response_type=code',
                'scope=' + encodeURIComponent('openid profile email'),
                'state=' + encodeURIComponent(state),
                'code_challenge=' + encodeURIComponent(codeChallenge),
                'code_challenge_method=S256'
            ];

            window.location.href = config.authorization_endpoint + '?' + params.join('&');
        });
    }

    /**
     * Handle the Okta callback after authorization.
     * Called from `okta-callback.html`. Validates state, exchanges the
     * authorization code for an Okta access token, then exchanges that
     * with the bridge for local JWT tokens.
     */
    function handleCallback() {
        var params = new URLSearchParams(window.location.search);
        var code = params.get('code');
        var state = params.get('state');
        var error = params.get('error');
        var errorDescription = params.get('error_description');

        var statusEl = document.getElementById('okta-callback-status');

        if (error) {
            if (statusEl) statusEl.textContent = errorDescription || error;
            setTimeout(function () {
                sessionStorage.setItem('okta_error', errorDescription || error);
                window.location.href = 'index.html';
            }, 2000);
            return;
        }

        if (!code) {
            if (statusEl) statusEl.textContent = 'No authorization code received';
            setTimeout(function () {
                sessionStorage.setItem('okta_error', 'No authorization code received');
                window.location.href = 'index.html';
            }, 2000);
            return;
        }

        // Validate state
        var savedState = sessionStorage.getItem('okta_state');
        if (state !== savedState) {
            if (statusEl) statusEl.textContent = 'Invalid state parameter';
            setTimeout(function () {
                sessionStorage.setItem('okta_error', 'Invalid state parameter');
                window.location.href = 'index.html';
            }, 2000);
            return;
        }

        var codeVerifier = sessionStorage.getItem('okta_code_verifier');
        sessionStorage.removeItem('okta_code_verifier');
        sessionStorage.removeItem('okta_state');

        if (statusEl) statusEl.textContent = 'Exchanging authorization code...';

        // First, get the Okta config to know the token endpoint
        fetch(API.BASE + '/auth/okta/config')
            .then(function (res) { return res.json(); })
            .then(function (oktaConfig) {
                if (!oktaConfig.enabled) throw new Error('Okta is not configured');
                if (oktaConfig.token_endpoint.indexOf('https://') !== 0) {
                    throw new Error('Token endpoint must use HTTPS');
                }

                // Exchange code for Okta access token
                var body = new URLSearchParams();
                body.append('grant_type', 'authorization_code');
                body.append('client_id', oktaConfig.client_id);
                body.append('code', code);
                body.append('redirect_uri', window.location.origin + '/okta-callback.html');
                body.append('code_verifier', codeVerifier);

                var controller = new AbortController();
                var timeoutId = setTimeout(function() { controller.abort(); }, 15000);

                return fetch(oktaConfig.token_endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString(),
                    signal: controller.signal
                }).finally(function() { clearTimeout(timeoutId); });
            })
            .then(function (res) {
                if (!res.ok) throw new Error('Token exchange failed');
                return res.json();
            })
            .then(function (tokenData) {
                if (!tokenData.access_token) throw new Error('No access token received');

                if (statusEl) statusEl.textContent = 'Authenticating with Impala...';

                // Exchange Okta access token with bridge for local JWT tokens
                return API.rawPost('/auth/okta', {
                    okta_token: tokenData.access_token
                });
            })
            .then(function (res) {
                if (!res.ok) {
                    return res.text().then(function (t) {
                        throw new Error(t || 'Bridge authentication failed');
                    });
                }
                return res.json();
            })
            .then(function (bridgeData) {
                if (!bridgeData.success) throw new Error(bridgeData.message || 'Authentication failed');

                // Store tokens
                API.setTokens(bridgeData.temporal_token, bridgeData.refresh_token);

                // Bootstrap roles
                var payload = API.parseJwt(bridgeData.refresh_token);
                var username = payload ? payload.sub : 'okta-user';
                Roles.bootstrap(username);

                if (statusEl) statusEl.textContent = 'Login successful! Redirecting...';
                window.location.href = 'dashboard.html';
            })
            .catch(function (err) {
                if (statusEl) statusEl.textContent = err.message || 'Authentication failed';
                setTimeout(function () {
                    sessionStorage.setItem('okta_error', err.message || 'Authentication failed');
                    window.location.href = 'index.html';
                }, 3000);
            });
    }

    return {
        init: init,
        startLogin: startLogin,
        handleCallback: handleCallback
    };
})();

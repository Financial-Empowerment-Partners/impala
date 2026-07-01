/**
 * Multi-provider OIDC SSO module (Okta / Auth0 / Duo / …).
 *
 * Handles the browser-side Authorization Code + PKCE flow for any provider
 * exposed by the bridge under `/auth/sso/:provider`. Provider config is
 * discovered at runtime from `GET {API.BASE}/auth/sso/:provider/config`; the
 * dashboard renders one button per enabled provider. No SDK, no client secret.
 *
 * @module SsoAuth
 */
var SsoAuth = (function () {
    // Per-provider discovery config, keyed by provider name.
    var configs = {};

    /**
     * Initialize SSO for the given provider names. For each, fetch its config
     * and render a login button when the provider is enabled on the bridge.
     * @param {string[]} providerNames
     */
    function init(providerNames) {
        providerNames = providerNames || ['okta', 'auth0', 'duo'];
        var container = document.getElementById('sso-buttons');
        var divider = document.getElementById('sso-divider');

        providerNames.forEach(function (name) {
            fetch(API.BASE + '/auth/sso/' + encodeURIComponent(name) + '/config')
                .then(function (res) {
                    if (!res.ok) throw new Error('Failed to fetch SSO config');
                    return res.json();
                })
                .then(function (data) {
                    if (!data || !data.enabled) return;
                    configs[name] = data;
                    if (divider) divider.classList.remove('hidden');
                    renderButton(name, container);
                })
                .catch(function () {
                    // Provider not available — no button.
                });
        });
    }

    /**
     * Render a "Sign in with <Provider>" button into the container.
     * @param {string} name
     * @param {HTMLElement} container
     */
    function renderButton(name, container) {
        if (!container) return;
        if (document.getElementById('sso-btn-' + name)) return;
        var label = name.charAt(0).toUpperCase() + name.slice(1);
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.id = 'sso-btn-' + name;
        btn.className = 'button expanded secondary';
        btn.textContent = 'Sign in with ' + label;
        btn.addEventListener('click', function () {
            startLogin(name);
        });
        container.appendChild(btn);
    }

    /**
     * Generate a cryptographically random string for PKCE code verifier / state.
     * @returns {string} URL-safe base64-encoded random string.
     */
    function generateCodeVerifier() {
        var bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        return base64UrlEncode(bytes);
    }

    /**
     * Generate a PKCE code challenge from a code verifier using SHA-256.
     * @param {string} verifier
     * @returns {Promise<string>}
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
     * Start the login flow for a provider. Generates PKCE, stores
     * provider-scoped state in sessionStorage, and redirects to the provider's
     * authorization endpoint. The provider name is encoded into `state` so a
     * single callback page can recover it.
     * @param {string} name
     */
    function startLogin(name) {
        var config = configs[name];
        if (!config || !config.enabled) return;

        var codeVerifier = generateCodeVerifier();
        var stateNonce = generateCodeVerifier();
        var state = name + ':' + stateNonce;

        generateCodeChallenge(codeVerifier).then(function (codeChallenge) {
            sessionStorage.setItem('sso_' + name + '_code_verifier', codeVerifier);
            sessionStorage.setItem('sso_' + name + '_state', state);

            var scope = (config.scopes && config.scopes.length)
                ? config.scopes.join(' ')
                : 'openid profile email';

            var params = [
                'client_id=' + encodeURIComponent(config.client_id),
                'redirect_uri=' + encodeURIComponent(window.location.origin + '/sso-callback.html'),
                'response_type=code',
                'scope=' + encodeURIComponent(scope),
                'state=' + encodeURIComponent(state),
                'code_challenge=' + encodeURIComponent(codeChallenge),
                'code_challenge_method=S256'
            ];

            // Auth0 only returns a JWT access token when an `audience` naming a
            // registered API is requested. The bridge reports `audience` distinct
            // from `client_id` for such providers; Okta/Duo leave them equal.
            if (config.audience && config.audience !== config.client_id) {
                params.push('audience=' + encodeURIComponent(config.audience));
            }

            window.location.href = config.authorization_endpoint + '?' + params.join('&');
        });
    }

    /**
     * Handle the SSO callback. Called from `sso-callback.html`. Recovers the
     * provider from `state`, validates it, exchanges the code with the
     * provider's token endpoint, then exchanges that token with the bridge for
     * local JWT tokens.
     */
    function handleCallback() {
        var params = new URLSearchParams(window.location.search);
        var code = params.get('code');
        var state = params.get('state');
        var error = params.get('error');
        var errorDescription = params.get('error_description');
        var statusEl = document.getElementById('sso-callback-status');

        function fail(msg) {
            if (statusEl) statusEl.textContent = msg;
            setTimeout(function () {
                sessionStorage.setItem('sso_error', msg);
                window.location.href = 'index.html';
            }, 2500);
        }

        if (error) {
            fail(errorDescription || error);
            return;
        }
        if (!code || !state) {
            fail('No authorization code received');
            return;
        }

        // Recover the provider name from the `state` prefix (`provider:nonce`).
        var sep = state.indexOf(':');
        if (sep < 1) {
            fail('Invalid state parameter');
            return;
        }
        var provider = state.substring(0, sep);

        var savedState = sessionStorage.getItem('sso_' + provider + '_state');
        if (state !== savedState) {
            fail('Invalid state parameter');
            return;
        }

        var codeVerifier = sessionStorage.getItem('sso_' + provider + '_code_verifier');
        sessionStorage.removeItem('sso_' + provider + '_code_verifier');
        sessionStorage.removeItem('sso_' + provider + '_state');

        if (statusEl) statusEl.textContent = 'Exchanging authorization code...';

        // Re-fetch the provider config to learn the token endpoint.
        fetch(API.BASE + '/auth/sso/' + encodeURIComponent(provider) + '/config')
            .then(function (res) { return res.json(); })
            .then(function (cfg) {
                if (!cfg.enabled) throw new Error('SSO provider is not configured');
                if (cfg.token_endpoint.indexOf('https://') !== 0) {
                    throw new Error('Token endpoint must use HTTPS');
                }

                var body = new URLSearchParams();
                body.append('grant_type', 'authorization_code');
                body.append('client_id', cfg.client_id);
                body.append('code', code);
                body.append('redirect_uri', window.location.origin + '/sso-callback.html');
                body.append('code_verifier', codeVerifier);

                var controller = new AbortController();
                var timeoutId = setTimeout(function () { controller.abort(); }, 15000);

                return fetch(cfg.token_endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString(),
                    signal: controller.signal
                }).finally(function () { clearTimeout(timeoutId); });
            })
            .then(function (res) {
                if (!res.ok) throw new Error('Token exchange failed');
                return res.json();
            })
            .then(function (tokenData) {
                if (!tokenData.access_token && !tokenData.id_token) {
                    throw new Error('No token received');
                }

                if (statusEl) statusEl.textContent = 'Authenticating with Impala...';

                // Send both tokens; the bridge validates the one its provider
                // config expects (access token, or id token for token_kind=id).
                return API.rawPost('/auth/sso/' + encodeURIComponent(provider), {
                    token: tokenData.access_token,
                    id_token: tokenData.id_token
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

                // Store tokens (namespaced to the active network). Authorization
                // is server-driven via the token's `role` claim.
                API.setTokens(bridgeData.temporal_token, bridgeData.refresh_token);

                if (statusEl) statusEl.textContent = 'Login successful! Redirecting...';
                window.location.href = 'dashboard.html';
            })
            .catch(function (err) {
                fail(err.message || 'Authentication failed');
            });
    }

    return {
        init: init,
        startLogin: startLogin,
        handleCallback: handleCallback
    };
})();

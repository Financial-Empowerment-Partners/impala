/**
 * Login page module — wires up the network selector, credential form, and
 * SSO provider buttons.
 *
 * Lives in its own file (rather than inline in index.html) so the CSP can
 * stay `script-src 'self'` with no 'unsafe-inline'.
 */
(function () {
    // Render the network selector so the user picks which bridge to log into.
    if (typeof Net !== 'undefined') {
        Net.mount('net-selector');
    }

    // Redirect if already logged in on the active network
    if (Auth.isLoggedIn()) {
        window.location.href = 'dashboard.html';
        return;
    }

    // Display callback errors from sessionStorage (multi-provider SSO flow,
    // plus the legacy Okta callback page's key).
    var errorDiv = document.getElementById('login-error');
    var callbackError =
        sessionStorage.getItem('sso_error') || sessionStorage.getItem('okta_error');
    if (callbackError) {
        errorDiv.textContent = callbackError;
        errorDiv.classList.remove('hidden');
        sessionStorage.removeItem('sso_error');
        sessionStorage.removeItem('okta_error');
    }

    // Initialize SSO (renders a button per enabled provider)
    SsoAuth.init(['okta', 'auth0', 'duo']);

    var form = document.getElementById('login-form');
    var loginBtn = document.getElementById('login-btn');

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        errorDiv.classList.add('hidden');

        var accountId = document.getElementById('account-id').value.trim();
        var password = document.getElementById('password').value;

        // Validate required fields
        var error = Validate.firstError([
            Validate.required(accountId),
            Validate.required(password)
        ]);
        if (error) {
            errorDiv.textContent = error;
            errorDiv.classList.remove('hidden');
            return;
        }

        API.setButtonLoading(loginBtn, true);

        Auth.login(accountId, password)
            .then(function () {
                window.location.href = 'dashboard.html';
            })
            .catch(function (err) {
                errorDiv.textContent = err.message || 'Login failed';
                errorDiv.classList.remove('hidden');
                API.setButtonLoading(loginBtn, false);
            });
    });
})();

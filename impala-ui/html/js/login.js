/**
 * Login page module — wires up the credential form and Okta button.
 *
 * Lives in its own file (rather than inline in index.html) so the CSP can
 * stay `script-src 'self'` with no 'unsafe-inline'.
 */
(function () {
    // Redirect if already logged in
    if (Auth.isLoggedIn()) {
        window.location.href = 'dashboard.html';
        return;
    }

    // Display callback errors from sessionStorage
    var errorDiv = document.getElementById('login-error');
    var callbackError = sessionStorage.getItem('okta_error');
    if (callbackError) {
        errorDiv.textContent = callbackError;
        errorDiv.classList.remove('hidden');
        sessionStorage.removeItem('okta_error');
    }

    // Initialize Okta (shows button if configured)
    OktaAuth.init();

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

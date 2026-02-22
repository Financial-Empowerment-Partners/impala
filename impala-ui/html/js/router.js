/**
 * Navigation and permission enforcement module.
 *
 * Handles:
 *  - Dynamic navigation bar construction with role-aware links
 *  - Active page highlighting with aria-current
 *  - Permission-based DOM element visibility (data-permission attributes)
 *  - Accessible toast notification display
 *  - Admin-only page guard
 *  - Session idle timer initialization
 *
 * @module Router
 */
var Router = (function () {
    /**
     * Initialize the page: check auth, build nav, highlight active link,
     * hide elements the current user lacks permission for, and start
     * the session idle timer.
     */
    function init() {
        if (!Auth.requireAuth()) return;
        buildNav();
        highlightActiveLink();
        enforcePermissions();
        // Start session idle timer if available
        if (typeof SessionTimer !== 'undefined') {
            SessionTimer.init();
        }
    }

    /**
     * Build the top navigation bar with links and user info.
     * The Admin link is only shown to users with the admin role.
     */
    function buildNav() {
        var nav = document.getElementById('main-nav');
        if (!nav) return;

        var username = Auth.getUsername() || 'Unknown';
        var role = Roles.currentUserRole();
        var roleDef = Roles.DEFINITIONS[role] || {};

        var links = [
            { href: 'dashboard.html', label: 'Dashboard' },
            { href: 'accounts.html', label: 'Accounts' },
            { href: 'mfa.html', label: 'MFA' },
            { href: 'transactions.html', label: 'Transactions' },
            { href: 'cards.html', label: 'Cards' }
        ];

        if (Roles.isAdmin()) {
            links.push({ href: 'admin.html', label: 'Admin' });
        }

        var html = '<div class="top-bar-left">' +
            '<ul class="menu">' +
            '<li class="menu-text"><strong>Impala</strong></li>';

        links.forEach(function (link) {
            html += '<li><a href="' + link.href + '">' + link.label + '</a></li>';
        });

        html += '</ul></div>' +
            '<div class="top-bar-right">' +
            '<ul class="menu">' +
            '<li class="menu-text">' + username + ' <span class="role-badge ' + role + '">' + (roleDef.label || role) + '</span></li>' +
            '<li><a href="#" id="logout-btn">Logout</a></li>' +
            '</ul></div>';

        nav.innerHTML = html;

        var logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', function (e) {
                e.preventDefault();
                // Stop session timer on logout
                if (typeof SessionTimer !== 'undefined') {
                    SessionTimer.stop();
                }
                Auth.logout();
            });
        }
    }

    /**
     * Add the 'active' CSS class and aria-current="page" to the nav link
     * matching the current page.
     */
    function highlightActiveLink() {
        var current = window.location.pathname.split('/').pop() || 'index.html';
        var links = document.querySelectorAll('#main-nav .menu a');
        for (var i = 0; i < links.length; i++) {
            var href = links[i].getAttribute('href');
            if (href === current) {
                links[i].parentElement.classList.add('active');
                links[i].setAttribute('aria-current', 'page');
            }
        }
    }

    /**
     * Hide DOM elements whose data-permission attribute specifies a permission
     * the current user does not have.
     */
    function enforcePermissions() {
        var elements = document.querySelectorAll('[data-permission]');
        for (var i = 0; i < elements.length; i++) {
            var el = elements[i];
            var permission = el.getAttribute('data-permission');
            if (!Roles.currentUserHasPermission(permission)) {
                el.classList.add('hidden');
            }
        }
    }

    /**
     * Display a temporary toast notification in the top-right corner.
     * Auto-dismisses after 4 seconds with a fade-out animation.
     * Uses ARIA live region attributes for screen reader accessibility.
     * @param {string} message - The notification text.
     * @param {string} [type='info'] - CSS class for styling: 'success', 'warning', 'alert', 'info'.
     */
    function showToast(message, type) {
        type = type || 'info';
        var container = document.getElementById('toast-container');
        if (!container) return;

        // Ensure container has ARIA live region attributes
        if (!container.hasAttribute('role')) {
            container.setAttribute('role', 'alert');
            container.setAttribute('aria-live', 'assertive');
            container.setAttribute('aria-atomic', 'true');
        }

        var toast = document.createElement('div');
        toast.className = 'toast ' + type;
        toast.textContent = message;
        container.appendChild(toast);

        setTimeout(function () {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, 4000);
    }

    /**
     * Guard for admin-only pages. Redirects to dashboard if the current
     * user does not have the admin role.
     * @returns {boolean} True if the user is admin.
     */
    function requireAdmin() {
        if (!Roles.isAdmin()) {
            window.location.href = 'dashboard.html';
            return false;
        }
        return true;
    }

    return {
        init: init,
        showToast: showToast,
        requireAdmin: requireAdmin,
        enforcePermissions: enforcePermissions
    };
})();

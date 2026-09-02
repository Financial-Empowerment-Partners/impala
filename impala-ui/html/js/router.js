/**
 * Navigation and permission enforcement module.
 *
 * Handles:
 *  - Dynamic navigation bar construction with role-aware links (the link
 *    model is a pure function, `linksForRole`, so the per-role nav is
 *    unit-testable without a DOM)
 *  - Responsive collapse: a hamburger button below the breakpoint
 *  - Active page highlighting with aria-current
 *  - Permission-based DOM element visibility (data-permission attributes)
 *  - Page guards: `requirePermission` renders an in-page explanation instead
 *    of silently bouncing — a treasurer following a shared deep link must
 *    learn why, not land on the dashboard wondering what broke
 *  - Accessible toasts split by severity: errors are assertive and persist,
 *    routine notices are polite and auto-dismiss (announcing everything
 *    assertively re-reads the whole stack to screen readers)
 *  - Session idle timer initialization
 *
 * @module Router
 */
var Router = (function () {
    // Delegates to the shared escaper: a text-node round trip escapes & < >
    // but NOT quotes, so values interpolated into double-quoted attributes
    // (value="...", title="...") could break out and inject attributes.
    function escapeHtml(str) {
        return EscapeHtml.escape(str);
    }

    /**
     * Pure nav model: which links a role sees, split into the ordinary
     * surfaces and the privileged group (rendered after a separator — the
     * visual grouping mirrors the capability model).
     * @param {string} role - Role key.
     * @returns {{main: Array, privileged: Array}}
     */
    function linksForRole(role) {
        var has = function (p) { return Roles.roleHasPermission(role, p); };
        var main = [
            { href: 'dashboard.html', label: 'Dashboard' },
            { href: 'accounts.html', label: 'Accounts' },
            { href: 'mfa.html', label: 'MFA' },
            { href: 'transactions.html', label: 'Transactions' },
            { href: 'cards.html', label: 'Cards' }
        ];
        var privileged = [];
        if (has('view_reserve') || has('manage_reserve')) {
            privileged.push({ href: 'reserve.html', label: 'Reserve' });
        }
        if (has('view_keys') || has('manage_keys')) {
            privileged.push({ href: 'keys.html', label: 'Keys' });
        }
        if (has('view_roles') || has('manage_roles')) {
            privileged.push({ href: 'admin.html', label: 'Roles' });
        }
        return { main: main, privileged: privileged };
    }

    /**
     * Pure toast ARIA model. Errors interrupt (assertive) and persist until
     * dismissed; everything else is polite and auto-dismisses.
     * @param {string} type - 'success' | 'warning' | 'alert' | 'info'.
     * @returns {{container: string, role: string, live: string, autoDismissMs: number}}
     */
    function toastAria(type) {
        if (type === 'alert') {
            return { container: 'toast-assertive', role: 'alert', live: 'assertive', autoDismissMs: 0 };
        }
        return { container: 'toast-polite', role: 'status', live: 'polite', autoDismissMs: 4000 };
    }

    /**
     * Initialize the page: check auth, build nav, highlight active link,
     * hide elements the current user lacks permission for, and start
     * the session idle timer.
     */
    function init() {
        if (!Auth.requireAuth()) return;
        if (typeof Theme !== 'undefined') {
            Theme.init();
        }
        // Live regions must exist in the accessibility tree BEFORE any toast
        // content lands in them, or the first announcement per severity is
        // unreliably delivered — create both up front, not lazily.
        toastContainer('toast-polite');
        toastContainer('toast-assertive');
        buildNav();
        highlightActiveLink();
        enforcePermissions();
        if (typeof SessionTimer !== 'undefined') {
            SessionTimer.init();
        }
    }

    /** Render one list of links as menu items. */
    function linkItems(links) {
        return links.map(function (link) {
            return '<li><a href="' + link.href + '">' + link.label + '</a></li>';
        }).join('');
    }

    /**
     * Build the top navigation bar with links and user info. Privileged
     * surfaces render after a separator; a role this build does not know
     * shows as a neutral badge carrying the raw claim (never mislabelled as
     * another role — during deploy skew a treasurer must not read as
     * "View Only" on the governance surface).
     */
    function buildNav() {
        var nav = document.getElementById('main-nav');
        if (!nav) return;

        var username = Auth.getUsername() || 'Unknown';
        var role = Roles.currentUserRole();
        var rawRole = Roles.rawUserRole ? Roles.rawUserRole() : role;
        var roleDef = Roles.getDefinition(rawRole);
        // Interpolated as a CSS class, so whitelist against known role keys.
        var roleClass = roleDef ? rawRole : 'unknown';
        var roleLabel = roleDef ? roleDef.label : rawRole;
        var links = linksForRole(role);

        var html = '<button type="button" class="nav-toggle" id="nav-toggle" aria-expanded="false" aria-controls="main-nav" aria-label="Menu">☰</button>' +
            '<div class="top-bar-left">' +
            '<ul class="menu">' +
            '<li class="menu-text brand"><span class="brand-mark" aria-hidden="true">◆</span><strong>Impala</strong></li>' +
            linkItems(links.main);
        if (links.privileged.length) {
            html += '<li class="nav-separator" role="separator" aria-hidden="true"></li>' +
                linkItems(links.privileged);
        }

        var darkActive = (typeof Theme !== 'undefined' && Theme.resolved() === 'dark');

        html += '</ul></div>' +
            '<div class="top-bar-right">' +
            '<ul class="menu">' +
            '<li class="net-selector-item" id="net-selector"></li>' +
            '<li><button type="button" class="theme-toggle" id="theme-toggle" aria-label="Toggle dark mode" aria-pressed="' + (darkActive ? 'true' : 'false') + '">' + (darkActive ? '☀' : '☾') + '</button></li>' +
            '<li class="menu-text">' + escapeHtml(username) + ' <span class="role-badge ' + roleClass + '">' + escapeHtml(roleLabel) + '</span></li>' +
            '<li><a href="#" id="logout-btn">Logout</a></li>' +
            '</ul></div>';

        nav.innerHTML = html;

        var logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', function (e) {
                e.preventDefault();
                if (typeof SessionTimer !== 'undefined') {
                    SessionTimer.stop();
                }
                Auth.logout();
            });
        }

        var themeToggle = document.getElementById('theme-toggle');
        if (themeToggle && typeof Theme !== 'undefined') {
            themeToggle.addEventListener('click', function () {
                var next = Theme.toggle();
                var isDark = next === 'dark';
                themeToggle.textContent = isDark ? '☀' : '☾';
                themeToggle.setAttribute('aria-pressed', isDark ? 'true' : 'false');
            });
        }

        var navToggle = document.getElementById('nav-toggle');
        if (navToggle) {
            navToggle.addEventListener('click', function () {
                var open = nav.classList.toggle('nav-open');
                navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
        }

        // Mount the two-bridge network selector into its placeholder.
        if (typeof Net !== 'undefined') {
            Net.mount('net-selector');
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

    /** Get (or lazily create) the severity-split toast containers. */
    function toastContainer(kind) {
        var outer = document.getElementById('toast-container');
        if (!outer) return null;
        var el = document.getElementById(kind);
        if (!el) {
            el = document.createElement('div');
            el.id = kind;
            // The live region must exist BEFORE content lands in it, or the
            // announcement is unreliable — which is why the containers are
            // persistent and per-severity instead of stamping role attributes
            // onto each transient toast.
            var aria = kind === 'toast-assertive'
                ? { role: 'alert', live: 'assertive' }
                : { role: 'status', live: 'polite' };
            el.setAttribute('role', aria.role);
            el.setAttribute('aria-live', aria.live);
            outer.appendChild(el);
        }
        return el;
    }

    /**
     * Display a toast notification. Errors ('alert') persist until dismissed;
     * other severities auto-dismiss. Every toast carries a dismiss button.
     * @param {string} message - The notification text.
     * @param {string} [type='info'] - 'success', 'warning', 'alert', 'info'.
     */
    function showToast(message, type) {
        type = type || 'info';
        var aria = toastAria(type);
        var container = toastContainer(aria.container);
        if (!container) return;

        var toast = document.createElement('div');
        toast.className = 'toast ' + type;
        var text = document.createElement('span');
        text.textContent = message;
        toast.appendChild(text);

        var close = document.createElement('button');
        close.type = 'button';
        close.className = 'toast-close';
        close.setAttribute('aria-label', 'Dismiss notification');
        close.textContent = '×';
        close.addEventListener('click', function () { remove(); });
        toast.appendChild(close);

        container.appendChild(toast);

        var removed = false;
        function remove() {
            if (removed) return;
            removed = true;
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }
        if (aria.autoDismissMs > 0) {
            setTimeout(remove, aria.autoDismissMs);
        }
    }

    /**
     * Page guard: require a permission or explain, in place, why the page is
     * unavailable — never a silent bounce. Returns true when access holds.
     * @param {string} permission - e.g. 'view_reserve'.
     * @param {string} pageLabel - Human name of the page, for the message.
     * @returns {boolean}
     */
    function requirePermission(permission, pageLabel) {
        if (Roles.currentUserHasPermission(permission)) return true;
        var role = Roles.currentUserRole();
        var def = Roles.getDefinition(role) || {};
        var container = document.querySelector('.grid-container');
        if (container) {
            container.innerHTML =
                '<div class="empty-state page-denied">' +
                '<div class="empty-state-icon" aria-hidden="true">🔒</div>' +
                '<h4>' + escapeHtml(pageLabel || 'This page') + ' is not part of your role</h4>' +
                '<p class="text-muted">You are signed in as <span class="role-badge ' +
                (Roles.isKnownRole(role) ? role : 'unknown') + '">' + escapeHtml(def.label || role) +
                '</span>, which does not include the <code>' + escapeHtml(permission) + '</code> permission.</p>' +
                '<p class="text-muted">If you need access, an admin can change your role from the Accounts page.</p>' +
                '<p><a class="button" href="dashboard.html">Back to dashboard</a></p>' +
                '</div>';
        }
        return false;
    }

    /**
     * Banner for pages a role can view but not act on. Read-only must be
     * legible as a role property, never mistaken for a broken page — an
     * auditor staring at a queue with no buttons deserves to know why.
     * @param {string} whatActions - e.g. 'Reserve actions'.
     * @param {string} whichRoles - e.g. 'the admin or treasurer role'.
     */
    function showReadOnlyBanner(whatActions, whichRoles) {
        var header = document.querySelector('.page-header');
        if (!header) return;
        var role = Roles.currentUserRole();
        var def = Roles.getDefinition(role) || {};
        var banner = document.createElement('div');
        banner.className = 'read-only-banner';
        banner.setAttribute('role', 'note');
        banner.innerHTML =
            '<span class="role-badge ' + (Roles.isKnownRole(role) ? role : 'unknown') + '">' +
            escapeHtml(def.label || role) + '</span> Read-only: your role can view this page. ' +
            escapeHtml(whatActions) + ' require ' + escapeHtml(whichRoles) + '.';
        header.appendChild(banner);
    }

    /**
     * Guard for admin-only pages. Kept for compatibility; now explains in
     * place like requirePermission instead of silently redirecting.
     * @returns {boolean} True if the user is admin.
     */
    function requireAdmin() {
        if (Roles.isAdmin()) return true;
        return requirePermission('manage_roles', 'This page');
    }

    return {
        init: init,
        linksForRole: linksForRole,
        toastAria: toastAria,
        showToast: showToast,
        requireAdmin: requireAdmin,
        requirePermission: requirePermission,
        showReadOnlyBanner: showReadOnlyBanner,
        enforcePermissions: enforcePermissions
    };
})();

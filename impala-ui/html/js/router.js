var Router = (function () {
    function init() {
        if (!Auth.requireAuth()) return;
        buildNav();
        highlightActiveLink();
        enforcePermissions();
    }

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
                Auth.logout();
            });
        }
    }

    function highlightActiveLink() {
        var current = window.location.pathname.split('/').pop() || 'index.html';
        var links = document.querySelectorAll('#main-nav .menu a');
        for (var i = 0; i < links.length; i++) {
            var href = links[i].getAttribute('href');
            if (href === current) {
                links[i].parentElement.classList.add('active');
            }
        }
    }

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

    function showToast(message, type) {
        type = type || 'info';
        var container = document.getElementById('toast-container');
        if (!container) return;

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

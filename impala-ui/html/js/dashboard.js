/**
 * Dashboard page module — displays system version, health status, and session info.
 *
 * Fetches build info from GET /api/version (build_date, rustc_version, schema_version),
 * performs a health check, and shows the current user's role, permissions, and token expiry.
 */
(function () {
    Router.init();

    // Version info
    API.get('/version')
        .then(function (data) {
            var html = '<table>' +
                '<tbody>';
            if (data.build_date) html += '<tr><td><strong>Build Date</strong></td><td>' + escapeHtml(data.build_date) + '</td></tr>';
            if (data.rustc_version) html += '<tr><td><strong>Rust Version</strong></td><td>' + escapeHtml(data.rustc_version) + '</td></tr>';
            if (data.schema_version !== undefined) html += '<tr><td><strong>Schema Version</strong></td><td>' + escapeHtml(String(data.schema_version)) + '</td></tr>';
            // Show any other fields
            Object.keys(data).forEach(function (key) {
                if (['build_date', 'rustc_version', 'schema_version'].indexOf(key) === -1) {
                    html += '<tr><td><strong>' + escapeHtml(key) + '</strong></td><td>' + escapeHtml(String(data[key])) + '</td></tr>';
                }
            });
            html += '</tbody></table>';
            document.getElementById('version-info').innerHTML = html;
        })
        .catch(function (err) {
            document.getElementById('version-info').innerHTML =
                '<span class="badge error">Error</span> ' + escapeHtml(err.message);
        });

    // Health check (against the active network's bridge)
    fetch(API.BASE + '/version')
        .then(function (res) {
            var status = res.ok ? 'ok' : 'error';
            var label = res.ok ? 'Healthy' : 'Unhealthy';
            document.getElementById('health-info').innerHTML =
                '<span class="badge ' + status + '">' + label + '</span>' +
                '<p style="margin-top:0.5rem">API endpoint responding (HTTP ' + res.status + ')</p>';
        })
        .catch(function () {
            document.getElementById('health-info').innerHTML =
                '<span class="badge error">Unreachable</span>' +
                '<p style="margin-top:0.5rem">Cannot reach the API server.</p>';
        });

    // Session info. The badge carries the RAW role claim (during deploy skew
    // a treasurer must never read as "View Only"), while capabilities and
    // quick links derive from the effective role, which fails closed.
    var username = Auth.getUsername() || 'Unknown';
    var role = Roles.currentUserRole();
    var rawRole = Roles.rawUserRole ? Roles.rawUserRole() : role;
    var roleDef = Roles.getDefinition(role) || {};
    var badgeDef = Roles.getDefinition(rawRole);
    // Interpolated as a CSS class, so whitelist against the known role keys
    // rather than escaping.
    var roleClass = badgeDef ? rawRole : 'unknown';
    var roleLabel = badgeDef ? badgeDef.label : rawRole;
    // Cookie sessions: the HttpOnly cookie's lifetime is server-enforced
    // (sliding 30-min idle window, 12-hour absolute cap) and not readable
    // from script — describe the policy instead of an expiry timestamp.
    var sessionStr = 'Expires after 15 min of inactivity';

    // Role grants revoke the target's sessions server-side, so the role shown
    // here is fixed for the life of this session — say so.
    var roleCell = '<span class="role-badge ' + roleClass + '">' + escapeHtml(roleLabel) + '</span>' +
        ' <span class="text-muted" style="font-size:0.8rem;">as of this sign-in</span>';
    if (roleDef.description) {
        roleCell += '<p class="text-muted" style="margin:0.35rem 0 0;font-size:0.85rem;">' +
            escapeHtml(roleDef.description) + '</p>';
    }

    var capCell = '<ul style="margin:0;list-style-position:inside;">' +
        capabilityPhrases(roleDef.permissions || []).map(function (c) {
            return '<li>' + escapeHtml(c) + '</li>';
        }).join('') +
        '</ul>';

    // Quick links to the privileged pages this role's nav includes (pure
    // model shared with the nav bar, so the two can never disagree).
    var privileged = Router.linksForRole(role).privileged;
    var linksRow = '';
    if (privileged.length) {
        linksRow = '<tr><td><strong>Quick Links</strong></td><td>' +
            privileged.map(function (l) {
                return '<a href="' + l.href + '">' + escapeHtml(l.label) + '</a>';
            }).join(' · ') + '</td></tr>';
    }

    document.getElementById('session-info').innerHTML =
        '<table><tbody>' +
        '<tr><td><strong>User</strong></td><td>' + escapeHtml(username) + '</td></tr>' +
        '<tr><td><strong>Role</strong></td><td>' + roleCell + '</td></tr>' +
        '<tr><td><strong>Session</strong></td><td>' + escapeHtml(sessionStr) + '</td></tr>' +
        '<tr><td><strong>Capabilities</strong></td><td>' + capCell + '</td></tr>' +
        linksRow +
        '</tbody></table>';

    /**
     * Humanize a role's permission set into short capability phrases.
     * Privileged surfaces get explicit phrases (read-only variants marked as
     * such); the ordinary view_/create_/manage_ ladder permissions collapse
     * into one summarizing line — enumerating them reads like a JWT dump.
     * @param {string[]} perms - The role's permission strings.
     * @returns {string[]} Human-readable capability phrases.
     */
    function capabilityPhrases(perms) {
        function has(p) { return perms.indexOf(p) !== -1; }
        var phrases = [];
        if (has('manage_roles')) phrases.push('Grant roles and govern accounts');
        if (has('manage_reserve')) {
            phrases.push('Move and reconcile reserve funds');
        } else if (has('view_reserve')) {
            phrases.push('View reserve state (read-only)');
        }
        if (has('manage_keys')) {
            phrases.push('Manage bridge keys and custodial seeds');
        } else if (has('view_keys')) {
            phrases.push('View the key inventory (read-only)');
        }
        if (has('view_accounts_list')) phrases.push('Browse all accounts');
        // One line for the day-to-day ladder surfaces.
        var ladderMutations = ['manage_accounts', 'delete_accounts', 'sync_profile',
            'manage_mfa', 'create_transactions', 'review_transactions', 'manage_cards'];
        phrases.push(ladderMutations.some(has)
            ? 'Work with accounts, MFA, transactions, and cards'
            : 'View accounts, MFA, transactions, and cards (read-only)');
        return phrases;
    }

    function escapeHtml(str) {
        return EscapeHtml.escape(str);
    }
})();

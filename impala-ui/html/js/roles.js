/**
 * Server-driven role-based access control (RBAC) module.
 *
 * The bridge is the source of truth for authorization: the temporal JWT
 * carries a `role` claim, this module reads it (via API.parseJwt) and maps
 * roles to permission sets for UI gating. UI permissions are DISPLAY gating
 * only — the bridge enforces capabilities server-side on every request, and
 * the two tables are pinned against the same fixture
 * (tests/fixtures/role-capabilities.json) so they cannot drift. Role grants
 * happen server-side (PUT /admin/accounts/:id/role); a grant revokes the
 * target's existing sessions, so the new role applies at their next sign-in.
 *
 * Old tokens without a `role` claim, an unauthenticated context, or a role
 * this build does not know (bridge deployed ahead of the UI) resolve to the
 * least-privileged `view-only` role (fail-closed).
 *
 * The original ladder (ascending privilege):
 *  - view-only: read access to accounts, MFA, transactions, cards
 *  - device:    + create_transactions, manage_cards
 *  - token:     + manage_accounts, manage_mfa
 *  - admin:     everything, including governance (role grants, deletion)
 *
 * Lateral privileged roles — specializations of the admin surface, none
 * includes another; admin remains the superset:
 *  - treasurer:     reserve & replenishment money operations
 *  - key-custodian: bridge credentials & custodial seeds
 *  - auditor:       read-only oversight of every privileged surface
 *
 * @module Roles
 */
var Roles = (function () {
    /**
     * Role definitions mapping role keys to their labels and permission sets.
     * @type {Object.<string, {label: string, permissions: string[]}>}
     */
    var DEFINITIONS = {
        'view-only': {
            label: 'View Only',
            permissions: ['view_accounts', 'view_mfa', 'view_transactions', 'view_cards']
        },
        'device': {
            label: 'Device',
            permissions: ['view_accounts', 'view_mfa', 'view_transactions', 'create_transactions', 'view_cards', 'manage_cards']
        },
        'token': {
            // review_transactions deliberately absent: the bridge requires
            // admin for PUT /transaction/:id/review, and a button that always
            // 403s is worse than none (this drift shipped once).
            label: 'Token',
            permissions: ['view_accounts', 'manage_accounts', 'view_mfa', 'manage_mfa', 'view_transactions', 'create_transactions', 'view_cards']
        },
        'treasurer': {
            label: 'Treasurer',
            description: 'Reserve & replenishment money operations: disbursement, refunds, write-offs, policy. No key custody, no governance.',
            permissions: ['view_accounts', 'view_mfa', 'view_transactions', 'view_cards', 'view_reserve', 'manage_reserve', 'view_roles']
        },
        'key-custodian': {
            label: 'Key Custodian',
            description: 'Bridge provider credentials and custodial Stellar seeds. No treasury operations, no governance.',
            permissions: ['view_accounts', 'view_accounts_list', 'view_mfa', 'view_transactions', 'view_cards', 'view_keys', 'manage_keys', 'view_roles']
        },
        'auditor': {
            label: 'Auditor',
            description: 'Read-only oversight of every privileged surface for compliance and reconciliation. Holds no privileged mutation.',
            permissions: ['view_accounts', 'view_accounts_list', 'view_mfa', 'view_transactions', 'view_cards', 'view_reserve', 'view_keys', 'view_roles']
        },
        'admin': {
            label: 'Admin',
            description: 'Everything, including governance: role grants, account deletion, directory sync, webhooks, transaction review.',
            permissions: ['view_accounts', 'view_accounts_list', 'manage_accounts', 'delete_accounts', 'sync_profile', 'view_mfa', 'manage_mfa', 'view_transactions', 'create_transactions', 'review_transactions', 'view_cards', 'manage_cards', 'view_roles', 'manage_roles', 'view_reserve', 'manage_reserve', 'view_keys', 'manage_keys']
        }
    };

    /** Least-privileged role used when no valid role can be determined. */
    var DEFAULT_ROLE = 'view-only';

    /**
     * Own-property definition lookup. DEFINITIONS is a plain object, so a
     * role claim named after an inherited property ('constructor',
     * 'toString', ...) would otherwise look truthy and crash or confuse
     * every consumer. The claim is server-validated, but a display/gating
     * layer must not trust that.
     * @param {string} role
     * @returns {object|undefined}
     */
    function getDefinition(role) {
        return Object.prototype.hasOwnProperty.call(DEFINITIONS, role)
            ? DEFINITIONS[role]
            : undefined;
    }

    /** Whether this build knows the role key. */
    function isKnownRole(role) {
        return getDefinition(role) !== undefined;
    }

    /**
     * Pure permission check for a given role (testable, no globals).
     * @param {string} role - Role key.
     * @param {string} permission - Permission string (e.g. 'manage_accounts').
     * @returns {boolean}
     */
    function roleHasPermission(role, permission) {
        var def = getDefinition(role);
        return def ? def.permissions.indexOf(permission) !== -1 : false;
    }

    /**
     * The current user's role, read from the temporal token's `role` claim.
     * Falls back to `view-only` when unauthenticated or for legacy tokens.
     * @returns {string}
     */
    function currentUserRole() {
        if (typeof API === 'undefined' || typeof API.getTemporalToken !== 'function') {
            return DEFAULT_ROLE;
        }
        var token = API.getTemporalToken();
        if (!token) return DEFAULT_ROLE;
        var payload = API.parseJwt(token);
        if (!payload || !payload.role) return DEFAULT_ROLE;
        return isKnownRole(payload.role) ? payload.role : DEFAULT_ROLE;
    }

    /**
     * The raw role claim from the token, before the known-role fallback —
     * for display surfaces that must never mislabel an unknown role as
     * view-only (deploy skew: bridge ahead of the UI). Authorization still
     * goes through currentUserRole(), which fails closed.
     * @returns {string}
     */
    function rawUserRole() {
        if (typeof API === 'undefined' || typeof API.getTemporalToken !== 'function') {
            return DEFAULT_ROLE;
        }
        var token = API.getTemporalToken();
        if (!token) return DEFAULT_ROLE;
        var payload = API.parseJwt(token);
        if (!payload || !payload.role) return DEFAULT_ROLE;
        return String(payload.role);
    }

    /** Check whether the currently logged-in user has a specific permission. */
    function currentUserHasPermission(permission) {
        return roleHasPermission(currentUserRole(), permission);
    }

    /** @returns {boolean} True if the current user has the admin role. */
    function isAdmin() {
        return currentUserRole() === 'admin';
    }

    // One-time cleanup: the legacy client-side role store is no longer used.
    if (typeof localStorage !== 'undefined') {
        try { localStorage.removeItem('impala_roles'); } catch (e) { /* ignore */ }
    }

    return {
        DEFINITIONS: DEFINITIONS,
        roleHasPermission: roleHasPermission,
        getDefinition: getDefinition,
        isKnownRole: isKnownRole,
        currentUserRole: currentUserRole,
        rawUserRole: rawUserRole,
        currentUserHasPermission: currentUserHasPermission,
        isAdmin: isAdmin
    };
})();

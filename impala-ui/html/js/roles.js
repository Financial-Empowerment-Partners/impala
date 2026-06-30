/**
 * Server-driven role-based access control (RBAC) module.
 *
 * The bridge is the source of truth for authorization: the temporal JWT carries
 * a `role` claim ("view-only" | "device" | "token" | "admin"). This module reads
 * that claim (via API.parseJwt) and maps roles to permission sets for UI gating.
 * There is no client-side role store anymore — role grants happen server-side
 * (PUT /admin/accounts/:id/role) and take effect at the target's next refresh.
 *
 * Old tokens without a `role` claim, or an unauthenticated context, resolve to
 * the least-privileged `view-only` role (fail-closed).
 *
 * Roles (ascending privilege):
 *  - view-only: read access to accounts, MFA, transactions, cards
 *  - device:    + create_transactions, manage_cards
 *  - token:     + manage_accounts, manage_mfa, review_transactions
 *  - admin:     all permissions (manage_roles, delete_accounts, sync_profile)
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
            label: 'Token',
            permissions: ['view_accounts', 'manage_accounts', 'view_mfa', 'manage_mfa', 'view_transactions', 'create_transactions', 'review_transactions', 'view_cards']
        },
        'admin': {
            label: 'Admin',
            permissions: ['view_accounts', 'manage_accounts', 'delete_accounts', 'sync_profile', 'view_mfa', 'manage_mfa', 'view_transactions', 'create_transactions', 'review_transactions', 'view_cards', 'manage_cards', 'manage_roles']
        }
    };

    /** Least-privileged role used when no valid role can be determined. */
    var DEFAULT_ROLE = 'view-only';

    /**
     * Pure permission check for a given role (testable, no globals).
     * @param {string} role - Role key.
     * @param {string} permission - Permission string (e.g. 'manage_accounts').
     * @returns {boolean}
     */
    function roleHasPermission(role, permission) {
        var def = DEFINITIONS[role];
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
        return DEFINITIONS[payload.role] ? payload.role : DEFAULT_ROLE;
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
        currentUserRole: currentUserRole,
        currentUserHasPermission: currentUserHasPermission,
        isAdmin: isAdmin
    };
})();

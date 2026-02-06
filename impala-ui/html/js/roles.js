/**
 * Client-side role-based access control (RBAC) module.
 *
 * Manages four roles with hierarchical permissions, persisted in localStorage.
 * The first user to log in is automatically bootstrapped as admin.
 *
 * Roles (ascending privilege):
 *  - view-only: read access to accounts, MFA, transactions, cards
 *  - device:    + create_transactions, manage_cards
 *  - token:     + manage_accounts, manage_mfa
 *  - admin:     + manage_roles (all permissions)
 *
 * @module Roles
 */
var Roles = (function () {
    /** localStorage key for the role assignments map. */
    var STORAGE_KEY = 'impala_roles';

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
            permissions: ['view_accounts', 'manage_accounts', 'view_mfa', 'manage_mfa', 'view_transactions', 'create_transactions', 'view_cards']
        },
        'admin': {
            label: 'Admin',
            permissions: ['view_accounts', 'manage_accounts', 'view_mfa', 'manage_mfa', 'view_transactions', 'create_transactions', 'view_cards', 'manage_cards', 'manage_roles']
        }
    };

    /**
     * Load the account-to-role mapping from localStorage.
     * @returns {Object.<string, string>} Map of accountId -> role key.
     */
    function loadRoles() {
        try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {};
        } catch (e) {
            return {};
        }
    }

    /** Persist the role mapping to localStorage. */
    function saveRoles(roles) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(roles));
    }

    /**
     * Get the role for an account. Defaults to 'view-only' if not assigned.
     * @param {string} accountId
     * @returns {string} Role key (e.g. 'admin', 'device').
     */
    function getRole(accountId) {
        var roles = loadRoles();
        return roles[accountId] || 'view-only';
    }

    /**
     * Assign a role to an account.
     * @param {string} accountId
     * @param {string} role - Must be a key in DEFINITIONS.
     * @returns {boolean} True if the role was valid and set.
     */
    function setRole(accountId, role) {
        if (!DEFINITIONS[role]) return false;
        var roles = loadRoles();
        roles[accountId] = role;
        saveRoles(roles);
        return true;
    }

    /** Remove the role assignment for an account (reverts to view-only). */
    function removeRole(accountId) {
        var roles = loadRoles();
        delete roles[accountId];
        saveRoles(roles);
    }

    /** @returns {Object.<string, string>} All account-to-role assignments. */
    function getAllAssignments() {
        return loadRoles();
    }

    /**
     * Check if an account has a specific permission.
     * @param {string} accountId
     * @param {string} permission - Permission string (e.g. 'manage_accounts').
     * @returns {boolean}
     */
    function hasPermission(accountId, permission) {
        var role = getRole(accountId);
        var def = DEFINITIONS[role];
        return def ? def.permissions.indexOf(permission) !== -1 : false;
    }

    /** Check if the currently logged-in user has a specific permission. */
    function currentUserHasPermission(permission) {
        var username = Auth.getUsername();
        if (!username) return false;
        return hasPermission(username, permission);
    }

    /** @returns {string} The current user's role key. */
    function currentUserRole() {
        var username = Auth.getUsername();
        if (!username) return 'view-only';
        return getRole(username);
    }

    /** @returns {boolean} True if the current user has the admin role. */
    function isAdmin() {
        return currentUserRole() === 'admin';
    }

    /**
     * Bootstrap role assignments on first login.
     * The very first account to log in is automatically granted admin.
     * Subsequent new accounts default to view-only.
     * @param {string} accountId - The account that just logged in.
     */
    function bootstrap(accountId) {
        var roles = loadRoles();
        if (Object.keys(roles).length === 0) {
            roles[accountId] = 'admin';
            saveRoles(roles);
        } else if (!roles[accountId]) {
            roles[accountId] = 'view-only';
            saveRoles(roles);
        }
    }

    return {
        DEFINITIONS: DEFINITIONS,
        getRole: getRole,
        setRole: setRole,
        removeRole: removeRole,
        getAllAssignments: getAllAssignments,
        hasPermission: hasPermission,
        currentUserHasPermission: currentUserHasPermission,
        currentUserRole: currentUserRole,
        isAdmin: isAdmin,
        bootstrap: bootstrap
    };
})();

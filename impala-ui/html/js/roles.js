var Roles = (function () {
    var STORAGE_KEY = 'impala_roles';

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

    function loadRoles() {
        try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {};
        } catch (e) {
            return {};
        }
    }

    function saveRoles(roles) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(roles));
    }

    function getRole(accountId) {
        var roles = loadRoles();
        return roles[accountId] || 'view-only';
    }

    function setRole(accountId, role) {
        if (!DEFINITIONS[role]) return false;
        var roles = loadRoles();
        roles[accountId] = role;
        saveRoles(roles);
        return true;
    }

    function removeRole(accountId) {
        var roles = loadRoles();
        delete roles[accountId];
        saveRoles(roles);
    }

    function getAllAssignments() {
        return loadRoles();
    }

    function hasPermission(accountId, permission) {
        var role = getRole(accountId);
        var def = DEFINITIONS[role];
        return def ? def.permissions.indexOf(permission) !== -1 : false;
    }

    function currentUserHasPermission(permission) {
        var username = Auth.getUsername();
        if (!username) return false;
        return hasPermission(username, permission);
    }

    function currentUserRole() {
        var username = Auth.getUsername();
        if (!username) return 'view-only';
        return getRole(username);
    }

    function isAdmin() {
        return currentUserRole() === 'admin';
    }

    function bootstrap(accountId) {
        var roles = loadRoles();
        // First user becomes admin
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

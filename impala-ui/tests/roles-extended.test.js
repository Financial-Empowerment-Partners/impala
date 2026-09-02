import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// roles.js reads the temporal token through the API global at call time, so a
// stub on globalThis controls exactly what role claim the module sees.
let Roles;
beforeAll(() => {
    Roles = loadScript('roles.js', 'Roles');
});

afterEach(() => {
    delete globalThis.API;
});

/** Install an API stub whose parsed JWT carries the given role claim. */
function stubTokenRole(role) {
    globalThis.API = {
        getTemporalToken: () => 'stub-token',
        parseJwt: () => ({ role })
    };
}

describe('currentUserRole with the new lateral role claims', () => {
    it.each(['treasurer', 'key-custodian', 'auditor'])(
        'recognizes the %s claim',
        (role) => {
            stubTokenRole(role);
            expect(Roles.currentUserRole()).toBe(role);
        }
    );

    it('falls back to view-only for an unknown claim (bridge-first deploys are safe)', () => {
        // A bridge deployed ahead of this UI may mint roles this build does
        // not know; authorization must fail closed, never guess upward.
        stubTokenRole('super-admin');
        expect(Roles.currentUserRole()).toBe('view-only');
        expect(Roles.currentUserHasPermission('manage_roles')).toBe(false);
    });

    it('rawUserRole returns the raw unknown claim for display surfaces', () => {
        // The badge must never mislabel an unknown role as view-only during
        // deploy skew; the raw claim is display-only, gating still fails closed.
        stubTokenRole('super-admin');
        expect(Roles.rawUserRole()).toBe('super-admin');
    });

    it('rawUserRole matches currentUserRole for a known claim', () => {
        stubTokenRole('treasurer');
        expect(Roles.rawUserRole()).toBe('treasurer');
    });
});

describe('lateral role isolation (no lateral role includes another)', () => {
    it('treasurer holds no key custody at all', () => {
        expect(Roles.roleHasPermission('treasurer', 'manage_keys')).toBe(false);
        expect(Roles.roleHasPermission('treasurer', 'view_keys')).toBe(false);
    });

    it('key-custodian holds no treasury access at all', () => {
        expect(Roles.roleHasPermission('key-custodian', 'manage_reserve')).toBe(false);
        expect(Roles.roleHasPermission('key-custodian', 'view_reserve')).toBe(false);
    });

    it('auditor holds no manage_* permission that exists anywhere', () => {
        // Loop over every permission any role defines, not a hand-picked list:
        // a new manage_* surface added to any role must not leak to auditor.
        const allPermissions = new Set();
        for (const def of Object.values(Roles.DEFINITIONS)) {
            for (const p of def.permissions) allPermissions.add(p);
        }
        const managePerms = [...allPermissions].filter((p) => p.startsWith('manage_'));
        expect(managePerms.length).toBeGreaterThan(0);
        for (const p of managePerms) {
            expect(Roles.roleHasPermission('auditor', p), `auditor must lack ${p}`).toBe(false);
        }
    });

    it('auditor is view-only in shape: every permission it holds is view_*', () => {
        for (const p of Roles.DEFINITIONS['auditor'].permissions) {
            expect(p, `auditor permission ${p} is not a view_* permission`).toMatch(/^view_/);
        }
    });
});

describe('admin as the strict superset', () => {
    it('holds every permission of every other role, plus at least one more', () => {
        const adminSet = new Set(Roles.DEFINITIONS['admin'].permissions);
        for (const [role, def] of Object.entries(Roles.DEFINITIONS)) {
            if (role === 'admin') continue;
            for (const p of def.permissions) {
                expect(adminSet.has(p), `admin must hold ${role}'s ${p}`).toBe(true);
            }
            // Strict: admin is never merely equal to another role.
            expect(adminSet.size).toBeGreaterThan(new Set(def.permissions).size);
        }
    });
});

describe('governance isolation', () => {
    // Governance stays admin-only on the bridge; a lateral role silently
    // gaining a governance permission in the UI would show controls that
    // always 403 — or worse, normalize the idea that it should work.
    const GOVERNANCE = ['manage_roles', 'delete_accounts', 'sync_profile', 'review_transactions'];
    it('no non-admin role holds any governance permission', () => {
        for (const role of Object.keys(Roles.DEFINITIONS)) {
            if (role === 'admin') continue;
            for (const perm of GOVERNANCE) {
                expect(Roles.roleHasPermission(role, perm),
                    `${role} must not hold ${perm}`).toBe(false);
            }
        }
    });

    it('the lateral roles hold exactly their documented permission sets', () => {
        // Pinned arrays, mirroring the bridge's expected_capability_roles
        // pattern: adding a permission to a lateral role must be a conscious
        // edit here, not a quiet drift.
        expect([...Roles.DEFINITIONS['treasurer'].permissions].sort()).toEqual([
            'manage_reserve', 'view_accounts', 'view_cards', 'view_mfa',
            'view_reserve', 'view_roles', 'view_transactions'
        ]);
        expect([...Roles.DEFINITIONS['key-custodian'].permissions].sort()).toEqual([
            'manage_keys', 'view_accounts', 'view_accounts_list', 'view_cards',
            'view_keys', 'view_mfa', 'view_roles', 'view_transactions'
        ]);
        expect([...Roles.DEFINITIONS['auditor'].permissions].sort()).toEqual([
            'view_accounts', 'view_accounts_list', 'view_cards', 'view_keys',
            'view_mfa', 'view_reserve', 'view_roles', 'view_transactions'
        ]);
    });
});

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { loadScript } from './helpers/load-script.js';

// The bridge asserts its authorization matrix against
// tests/fixtures/role-capabilities.json and this suite asserts the UI's
// permission table (roles.js DEFINITIONS) against the same file, so the two
// stacks cannot drift apart silently. UI permissions are display gating only;
// the bridge enforces server-side — but a UI that shows a page the bridge
// 403s (or hides one it allows) is a lie either way.
const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
    readFileSync(resolve(here, 'fixtures', 'role-capabilities.json'), 'utf8'));

let Roles;
beforeAll(() => {
    Roles = loadScript('roles.js', 'Roles');
});

/**
 * The set of UI roles holding a permission — EXPLICITLY. No manage-implies-
 * view softening here: the actual page guards check the single named
 * permission (reserve.js requirePermission('view_reserve'), keys.js
 * requirePermission('view_keys')), so a role missing the explicit view_*
 * permission is locked out of the page no matter what it can manage. A
 * mutation test proved the softened comparison masked exactly that drift.
 * The "every manager can also view" expectation is enforced as its own
 * invariant below instead.
 */
function rolesWithUiPermission(permission) {
    return Object.keys(Roles.DEFINITIONS).filter((role) =>
        Roles.roleHasPermission(role, permission));
}

describe('manage implies view (page-guard invariant)', () => {
    // requirePermission checks one permission, so any role holding manage_X
    // without view_X could mutate a surface it cannot open — a broken page,
    // caught here rather than in production.
    const SURFACES = ['reserve', 'keys'];
    it.each(SURFACES)('every role with manage_%s also holds view_%s', (surface) => {
        for (const role of Object.keys(Roles.DEFINITIONS)) {
            if (Roles.roleHasPermission(role, 'manage_' + surface)) {
                expect(Roles.roleHasPermission(role, 'view_' + surface),
                    `${role} holds manage_${surface} without view_${surface}`).toBe(true);
            }
        }
    });
});

describe('fixture roles vs UI DEFINITIONS', () => {
    it('agree as sets', () => {
        expect([...fixture.roles].sort())
            .toEqual(Object.keys(Roles.DEFINITIONS).sort());
    });

    it('agree in the documented order (ladder ascending, then lateral, then admin)', () => {
        expect(fixture.roles).toEqual(Object.keys(Roles.DEFINITIONS));
    });
});

describe('capability parity with the UI permission table', () => {
    // Bridge capability -> UI permission, for every capability with a UI page.
    const PARITY = [
        ['ManageReserve', 'manage_reserve'],
        ['ReadReserve', 'view_reserve'],
        ['ManageKeys', 'manage_keys'],
        ['ReadKeys', 'view_keys'],
        ['ReadAccounts', 'view_accounts_list']
    ];

    it.each(PARITY)('%s holders equal the roles with %s', (capability, permission) => {
        expect(fixture.capabilities[capability], `${capability} missing from fixture`)
            .toBeDefined();
        expect([...fixture.capabilities[capability]].sort())
            .toEqual(rolesWithUiPermission(permission).sort());
    });
});

describe('capabilities without a UI counterpart', () => {
    // ReadTransactions and ReadEvents gate bridge API surfaces (transaction
    // export, event/audit feeds) that have no dedicated UI page yet — the
    // existing Transactions page is gated by the ladder's view_transactions,
    // which every role holds, not by these privileged capabilities. Until a
    // page exists there is no UI permission to pin them to, so this suite
    // only pins their shape: present, and granted to known roles.
    it.each(['ReadTransactions', 'ReadEvents'])(
        '%s exists and names only known roles',
        (capability) => {
            const holders = fixture.capabilities[capability];
            expect(holders, `${capability} missing from fixture`).toBeDefined();
            expect(Array.isArray(holders)).toBe(true);
            for (const role of holders) {
                expect(fixture.roles, `${capability} names unknown role ${role}`)
                    .toContain(role);
            }
        }
    );
});

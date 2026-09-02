import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// roles.js guards its API / localStorage access with typeof checks, so it loads
// cleanly under Node with neither defined.
let Roles;
beforeAll(() => {
    Roles = loadScript('roles.js', 'Roles');
});

describe('Roles.DEFINITIONS', () => {
    it('defines the seven roles', () => {
        expect(Object.keys(Roles.DEFINITIONS).sort()).toEqual(
            ['admin', 'auditor', 'device', 'key-custodian', 'token', 'treasurer', 'view-only']);
    });
});

describe('Roles.roleHasPermission', () => {
    it('admin has every new permission', () => {
        expect(Roles.roleHasPermission('admin', 'manage_roles')).toBe(true);
        expect(Roles.roleHasPermission('admin', 'manage_reserve')).toBe(true);
        expect(Roles.roleHasPermission('admin', 'delete_accounts')).toBe(true);
        expect(Roles.roleHasPermission('admin', 'sync_profile')).toBe(true);
        expect(Roles.roleHasPermission('admin', 'review_transactions')).toBe(true);
    });

    it('token cannot review transactions (bridge requires admin — a button that always 403s is a lie)', () => {
        expect(Roles.roleHasPermission('token', 'review_transactions')).toBe(false);
        expect(Roles.roleHasPermission('token', 'delete_accounts')).toBe(false);
        expect(Roles.roleHasPermission('token', 'manage_roles')).toBe(false);
        expect(Roles.roleHasPermission('token', 'manage_reserve')).toBe(false);
        expect(Roles.roleHasPermission('token', 'sync_profile')).toBe(false);
    });

    it('view-only can only view', () => {
        expect(Roles.roleHasPermission('view-only', 'view_accounts')).toBe(true);
        expect(Roles.roleHasPermission('view-only', 'manage_accounts')).toBe(false);
        expect(Roles.roleHasPermission('view-only', 'review_transactions')).toBe(false);
    });

    it('device can manage cards and create transactions but not review', () => {
        expect(Roles.roleHasPermission('device', 'create_transactions')).toBe(true);
        expect(Roles.roleHasPermission('device', 'manage_cards')).toBe(true);
        expect(Roles.roleHasPermission('device', 'review_transactions')).toBe(false);
    });

    it('returns false for an unknown role', () => {
        expect(Roles.roleHasPermission('bogus', 'view_accounts')).toBe(false);
    });
});

describe('Roles default (unauthenticated) behaviour', () => {
    it('currentUserRole defaults to view-only with no token/API', () => {
        expect(Roles.currentUserRole()).toBe('view-only');
    });

    it('isAdmin is false by default', () => {
        expect(Roles.isAdmin()).toBe(false);
    });

    it('currentUserHasPermission reflects the default view-only role', () => {
        expect(Roles.currentUserHasPermission('view_accounts')).toBe(true);
        expect(Roles.currentUserHasPermission('manage_roles')).toBe(false);
    });
});

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// router.js's IIFE only defines functions at load time; EscapeHtml and Roles
// are resolved at call time from the global scope, so the modules load under
// plain Node with no stubs. The real Roles module is installed on globalThis
// so linksForRole/requirePermission exercise the actual permission table, not
// a mock of it.
let Roles;
let Router;
beforeAll(() => {
    globalThis.EscapeHtml = loadScript('escape-html.js', 'EscapeHtml');
    Roles = loadScript('roles.js', 'Roles');
    globalThis.Roles = Roles;
    Router = loadScript('router.js', 'Router');
});

afterAll(() => {
    delete globalThis.Roles;
    delete globalThis.EscapeHtml;
});

const MAIN_LABELS = ['Dashboard', 'Accounts', 'MFA', 'Transactions', 'Cards'];

/** The privileged nav labels a role sees. */
function privilegedLabels(role) {
    return Router.linksForRole(role).privileged.map((l) => l.label);
}

describe('Router.linksForRole', () => {
    it('shows the same main links to every role', () => {
        for (const role of Object.keys(Roles.DEFINITIONS)) {
            expect(Router.linksForRole(role).main.map((l) => l.label))
                .toEqual(MAIN_LABELS);
        }
    });

    it('shows no privileged links to the original non-privileged ladder', () => {
        expect(privilegedLabels('view-only')).toEqual([]);
        expect(privilegedLabels('device')).toEqual([]);
        expect(privilegedLabels('token')).toEqual([]);
    });

    it('treasurer sees Reserve and Roles but never Keys', () => {
        expect(privilegedLabels('treasurer')).toEqual(['Reserve', 'Roles']);
    });

    it('key-custodian sees Keys and Roles but never Reserve', () => {
        expect(privilegedLabels('key-custodian')).toEqual(['Keys', 'Roles']);
    });

    it('auditor sees every privileged surface (read-only oversight)', () => {
        expect(privilegedLabels('auditor')).toEqual(['Reserve', 'Keys', 'Roles']);
    });

    it('admin sees every privileged surface', () => {
        expect(privilegedLabels('admin')).toEqual(['Reserve', 'Keys', 'Roles']);
    });

    it('privileged links carry the expected hrefs', () => {
        expect(Router.linksForRole('admin').privileged).toEqual([
            { href: 'reserve.html', label: 'Reserve' },
            { href: 'keys.html', label: 'Keys' },
            { href: 'admin.html', label: 'Roles' }
        ]);
    });
});

describe('Router.toastAria', () => {
    it('errors are assertive, land in the alert container, and never auto-dismiss', () => {
        expect(Router.toastAria('alert')).toEqual({
            container: 'toast-assertive',
            role: 'alert',
            live: 'assertive',
            autoDismissMs: 0
        });
    });

    it.each(['success', 'info', 'warning'])(
        '%s is polite status and auto-dismisses',
        (type) => {
            const aria = Router.toastAria(type);
            expect(aria.container).toBe('toast-polite');
            expect(aria.role).toBe('status');
            expect(aria.live).toBe('polite');
            expect(aria.autoDismissMs).toBeGreaterThan(0);
        }
    );
});

describe('Router.requirePermission', () => {
    // With no API global, Roles.currentUserRole() fails closed to view-only —
    // so view_accounts is granted and manage_roles is denied.
    afterEach(() => {
        delete globalThis.document;
    });

    it('returns true for a granted permission without touching the DOM', () => {
        // No document stub at all: the granted path must return before any
        // DOM access, or every page would crash for authorized users.
        expect(Router.requirePermission('view_accounts', 'Accounts')).toBe(true);
    });

    it('returns false for a denied permission', () => {
        // The denied path renders an in-page explanation into .grid-container;
        // querySelector returning null exercises the container-missing guard
        // while still asserting the boolean the page guard keys off.
        globalThis.document = { querySelector: () => null };
        expect(Router.requirePermission('manage_roles', 'Roles')).toBe(false);
    });
});

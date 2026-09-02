import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// theme.js guards document/localStorage/matchMedia (typeof checks and
// try/catch), so it loads and resolves under Node with none of them defined.
let Theme;
beforeAll(() => {
    Theme = loadScript('theme.js', 'Theme');
});

describe('Theme.resolve (pure precedence)', () => {
    it('an explicit dark choice beats either system preference', () => {
        expect(Theme.resolve('dark', false)).toBe('dark');
        expect(Theme.resolve('dark', true)).toBe('dark');
    });

    it('an explicit light choice beats either system preference', () => {
        expect(Theme.resolve('light', false)).toBe('light');
        expect(Theme.resolve('light', true)).toBe('light');
    });

    it('no stored choice follows the system', () => {
        expect(Theme.resolve(null, true)).toBe('dark');
        expect(Theme.resolve(null, false)).toBe('light');
        expect(Theme.resolve(undefined, true)).toBe('dark');
        expect(Theme.resolve(undefined, false)).toBe('light');
    });

    it('a garbage stored value follows the system, never renders literally', () => {
        expect(Theme.resolve('blue', true)).toBe('dark');
        expect(Theme.resolve('blue', false)).toBe('light');
        expect(Theme.resolve('', true)).toBe('dark');
        expect(Theme.resolve('DARK', false)).toBe('light');
    });
});

describe('Theme without a DOM', () => {
    it('resolved() does not throw and falls back to light', () => {
        // No localStorage and no matchMedia: the unknowable system preference
        // reads as light, the fail-safe default.
        expect(() => Theme.resolved()).not.toThrow();
        expect(Theme.resolved()).toBe('light');
    });

    it('get() aliases resolved() and does not throw', () => {
        expect(() => Theme.get()).not.toThrow();
        expect(Theme.get()).toBe(Theme.resolved());
    });
});

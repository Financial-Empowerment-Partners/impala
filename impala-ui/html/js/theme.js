/**
 * Light/dark theme module, three-state: an explicit choice ('light'/'dark')
 * persisted in localStorage under `impala_theme`, or no stored value, which
 * follows the operating system via prefers-color-scheme (and tracks live OS
 * changes until the user chooses explicitly). The resolution is a pure
 * function, `resolve`, so the precedence — explicit choice beats system —
 * is unit-testable without a DOM.
 *
 * The dark palette keys off `data-theme="dark"` on the document root, and
 * `color-scheme` is set alongside it so native controls (scrollbars,
 * selects, date pickers) match the rendered theme.
 *
 * @module Theme
 */
var Theme = (function () {
    var STORAGE_KEY = 'impala_theme';

    /**
     * Pure resolution: what theme should render given the stored choice and
     * the system preference. An explicit stored choice always wins — the
     * toggle persists one, so toggling away from the system theme sticks.
     * @param {string|null} stored - 'light', 'dark', or null/unknown.
     * @param {boolean} systemPrefersDark
     * @returns {string} 'light' or 'dark'.
     */
    function resolve(stored, systemPrefersDark) {
        if (stored === 'dark') return 'dark';
        if (stored === 'light') return 'light';
        return systemPrefersDark ? 'dark' : 'light';
    }

    /** @returns {string|null} The explicitly stored choice, or null. */
    function stored() {
        try {
            var v = localStorage.getItem(STORAGE_KEY);
            return v === 'dark' || v === 'light' ? v : null;
        } catch (e) {
            return null;
        }
    }

    /** @returns {boolean} Whether the OS prefers dark (false when unknowable). */
    function systemPrefersDark() {
        try {
            return typeof window !== 'undefined'
                && typeof window.matchMedia === 'function'
                && window.matchMedia('(prefers-color-scheme: dark)').matches;
        } catch (e) {
            return false;
        }
    }

    /** The theme that should currently render. */
    function resolved() {
        return resolve(stored(), systemPrefersDark());
    }

    /** Back-compat alias: the effective theme ('light' or 'dark'). */
    function get() {
        return resolved();
    }

    /** Reflect a theme on the document root without persisting it. */
    function apply(theme) {
        if (typeof document === 'undefined') return;
        var root = document.documentElement;
        if (theme === 'dark') {
            root.setAttribute('data-theme', 'dark');
        } else {
            root.removeAttribute('data-theme');
        }
        root.style.colorScheme = theme === 'dark' ? 'dark' : 'light';
    }

    /** Persist an explicit choice and apply it. */
    function set(theme) {
        var normalized = theme === 'dark' ? 'dark' : 'light';
        try {
            localStorage.setItem(STORAGE_KEY, normalized);
        } catch (e) { /* storage unavailable — apply in-memory only */ }
        apply(normalized);
    }

    /**
     * Toggle from the currently rendered theme; the result becomes an
     * explicit choice (system-following ends at the first toggle).
     * @returns {string} The new theme.
     */
    function toggle() {
        var next = resolved() === 'dark' ? 'light' : 'dark';
        set(next);
        return next;
    }

    /** Apply the resolved theme (safe to call repeatedly). */
    function init() {
        apply(resolved());
    }

    var api = {
        resolve: resolve,
        resolved: resolved,
        get: get,
        apply: apply,
        set: set,
        toggle: toggle,
        init: init
    };

    // Apply ASAP so the page does not flash the wrong theme, and track live
    // OS switches while no explicit choice is stored.
    if (typeof document !== 'undefined') {
        try { apply(resolved()); } catch (e) { /* ignore */ }
        try {
            if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
                window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
                    if (stored() === null) apply(resolved());
                });
            }
        } catch (e) { /* older browsers: no live tracking */ }
    }

    return api;
})();

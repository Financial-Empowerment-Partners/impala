/**
 * Light/dark theme module.
 *
 * Persists the choice in localStorage under `impala_theme` and reflects it on
 * the document root via `data-theme="dark"` (the stylesheet keys all dark
 * overrides off that attribute). Applies the saved theme immediately on load to
 * avoid a flash of the wrong theme.
 *
 * @module Theme
 */
var Theme = (function () {
    var STORAGE_KEY = 'impala_theme';

    /** @returns {string} 'light' or 'dark' (defaults to 'light'). */
    function get() {
        try {
            return localStorage.getItem(STORAGE_KEY) === 'dark' ? 'dark' : 'light';
        } catch (e) {
            return 'light';
        }
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
    }

    /** Persist and apply a theme. */
    function set(theme) {
        var normalized = theme === 'dark' ? 'dark' : 'light';
        try {
            localStorage.setItem(STORAGE_KEY, normalized);
        } catch (e) { /* storage unavailable — apply in-memory only */ }
        apply(normalized);
    }

    /**
     * Toggle between light and dark.
     * @returns {string} The new theme.
     */
    function toggle() {
        var next = get() === 'dark' ? 'light' : 'dark';
        set(next);
        return next;
    }

    /** Apply the persisted theme (safe to call repeatedly). */
    function init() {
        apply(get());
    }

    var api = { get: get, apply: apply, set: set, toggle: toggle, init: init };

    // Apply ASAP so the page does not flash the default theme.
    if (typeof document !== 'undefined') {
        try { apply(get()); } catch (e) { /* ignore */ }
    }

    return api;
})();

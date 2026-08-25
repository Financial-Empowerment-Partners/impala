import js from '@eslint/js';

/**
 * Flat ESLint config for the vanilla-JS dashboard.
 *
 * The browser modules are plain <script> files (sourceType "script") that
 * communicate through IIFE named globals (API, Roles, Net, …). Those globals are
 * declared writable here so that `var Foo = (function(){…})()` in one file and a
 * reference to `Foo` in another are both accepted, and `no-redeclare` is off for
 * the same reason.
 */
export default [
    js.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2021,
            sourceType: 'script',
            globals: {
                // Browser environment
                window: 'readonly',
                document: 'readonly',
                localStorage: 'readonly',
                sessionStorage: 'readonly',
                fetch: 'readonly',
                crypto: 'readonly',
                navigator: 'readonly',
                location: 'readonly',
                history: 'readonly',
                console: 'readonly',
                setTimeout: 'readonly',
                clearTimeout: 'readonly',
                setInterval: 'readonly',
                clearInterval: 'readonly',
                requestAnimationFrame: 'readonly',
                cancelAnimationFrame: 'readonly',
                atob: 'readonly',
                btoa: 'readonly',
                alert: 'readonly',
                confirm: 'readonly',
                prompt: 'readonly',
                TextEncoder: 'readonly',
                URL: 'readonly',
                URLSearchParams: 'readonly',
                AbortController: 'readonly',
                Event: 'readonly',
                CustomEvent: 'readonly',
                HTMLElement: 'readonly',
                Node: 'readonly',
                $: 'readonly',

                // IIFE named globals shared across files
                IMPALA_CONFIG: 'writable',
                API: 'writable',
                Auth: 'writable',
                Roles: 'writable',
                Router: 'writable',
                Validate: 'writable',
                Paginate: 'writable',
                SessionTimer: 'writable',
                SsoAuth: 'writable',
                OktaAuth: 'writable',
                EscapeHtml: 'writable',
                NetConfig: 'writable',
                Net: 'writable',
                Theme: 'writable',
                Modal: 'writable',
                Drawer: 'writable',
                TxFilter: 'writable',
                ReserveMath: 'writable',
                KeysView: 'writable'
            }
        },
        rules: {
            'no-redeclare': 'off',
            'no-unused-vars': 'off',
            'no-empty': ['error', { allowEmptyCatch: true }]
        }
    }
];

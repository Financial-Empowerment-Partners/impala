/**
 * Runtime configuration for the Impala admin dashboard.
 *
 * This file is loaded first on every page (before api.js) and is intended to be
 * edited by operators without a rebuild — the static bundle never changes, only
 * this file. It declares the set of Stellar networks the dashboard can target
 * and the `/api/<network>` base path each one is proxied to by Nginx.
 *
 * Two-bridge routing: each bridge deployment serves a single Stellar network, so
 * the dashboard routes `/api/testnet/*` and `/api/mainnet/*` to the matching
 * bridge. Tokens are namespaced per network (JWTs are not portable across
 * bridges) — see net-config.js / api.js.
 */
window.IMPALA_CONFIG = {
    networks: {
        testnet: { base: '/api/testnet', label: 'Testnet' },
        mainnet: { base: '/api/mainnet', label: 'Mainnet' }
    },
    default: 'testnet'
};

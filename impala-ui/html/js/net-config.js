/**
 * Pure network-configuration helpers (no DOM / storage / globals at load time).
 *
 * Resolves the active network from a config object + a (possibly stale or
 * missing) selected key, and namespaces storage keys per network so that JWTs
 * issued by one bridge are never sent to another.
 *
 * Kept side-effect-free so it can be unit-tested via tests/helpers/load-script.js.
 *
 * @module NetConfig
 */
var NetConfig = (function () {
    /** Fallback base path used when no config/network can be resolved. */
    var FALLBACK_BASE = '/api';

    /**
     * List the configured networks as an ordered array.
     * @param {Object} cfg - The IMPALA_CONFIG-shaped object.
     * @returns {Array<{key: string, label: string, base: string}>}
     */
    function listNetworks(cfg) {
        if (!cfg || !cfg.networks) return [];
        return Object.keys(cfg.networks).map(function (key) {
            var net = cfg.networks[key] || {};
            return { key: key, label: net.label || key, base: net.base || FALLBACK_BASE };
        });
    }

    /**
     * Resolve the effective network key.
     * Prefers `selected` when it names a configured network, then the config
     * default, then the first configured network. Returns null if none exist.
     * @param {Object} cfg
     * @param {string|null} selected - The persisted/selected network key.
     * @returns {string|null}
     */
    function resolveKey(cfg, selected) {
        if (!cfg || !cfg.networks) return null;
        if (selected && cfg.networks[selected]) return selected;
        if (cfg.default && cfg.networks[cfg.default]) return cfg.default;
        var keys = Object.keys(cfg.networks);
        return keys.length ? keys[0] : null;
    }

    /**
     * Resolve the API base path for the effective network.
     * @param {Object} cfg
     * @param {string|null} selected
     * @returns {string} e.g. '/api/testnet', or '/api' as a last resort.
     */
    function resolveBase(cfg, selected) {
        var key = resolveKey(cfg, selected);
        if (key === null) return FALLBACK_BASE;
        return cfg.networks[key].base || FALLBACK_BASE;
    }

    /**
     * Build a per-network storage key, e.g. tokenKey('temporal_token','mainnet')
     * → 'temporal_token::mainnet'. When no network key is given, the bare name
     * is returned (backwards-compatible).
     * @param {string} name
     * @param {string|null} networkKey
     * @returns {string}
     */
    function tokenKey(name, networkKey) {
        if (!networkKey) return name;
        return name + '::' + networkKey;
    }

    return {
        listNetworks: listNetworks,
        resolveKey: resolveKey,
        resolveBase: resolveBase,
        tokenKey: tokenKey
    };
})();

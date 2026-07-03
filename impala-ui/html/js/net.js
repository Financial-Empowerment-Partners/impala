/**
 * Network selector UI (two-bridge routing).
 *
 * Renders a network indicator + dropdown (used in the top bar and on the login
 * page). Switching network persists the choice under `impala_network`; because
 * each bridge issues its own non-portable JWTs, switching to a bridge the user
 * is not authenticated on redirects to the login page, otherwise it reloads so
 * the page re-fetches against the new bridge. `confirmLive()` calls the public
 * `GET /network` endpoint to confirm the proxy points where the label claims.
 *
 * Pure resolution logic lives in net-config.js; this module is the DOM glue.
 *
 * @module Net
 */
var Net = (function () {
    var STORAGE_KEY = 'impala_network';

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str == null ? '' : str));
        return div.innerHTML;
    }

    function config() {
        return (typeof window !== 'undefined' && window.IMPALA_CONFIG) ? window.IMPALA_CONFIG : null;
    }

    /** @returns {string|null} The active network key. */
    function current() {
        return API.currentNetworkKey();
    }

    /**
     * Whether a valid (non-expired) refresh token exists for a given network.
     * @param {string} key
     * @returns {boolean}
     */
    function isAuthedOn(key) {
        if (typeof NetConfig === 'undefined') return false;
        var storageKey = NetConfig.tokenKey('refresh_token', key);
        var token = null;
        try { token = localStorage.getItem(storageKey); } catch (e) { return false; }
        return !!token && !API.isTokenExpired(token);
    }

    /**
     * Persist a network choice and route appropriately. No-op if unchanged.
     * @param {string} key
     */
    function switchTo(key) {
        var cfg = config();
        if (!cfg || !cfg.networks || !cfg.networks[key]) return;
        if (key === current()) return;
        try { localStorage.setItem(STORAGE_KEY, key); } catch (e) { /* ignore */ }

        if (!isAuthedOn(key)) {
            // Separate auth per bridge — send the user to log in on the target.
            window.location.href = 'index.html';
        } else {
            window.location.reload();
        }
    }

    /**
     * Confirm the proxy for a network actually serves that network by calling
     * the public GET /network endpoint on the active base.
     * @returns {Promise<{ok: boolean, stellar_network: string|null}>}
     */
    function confirmLive() {
        return fetch(API.BASE + '/network', {
            headers: { 'Accept': 'application/json' }
        }).then(function (res) {
            if (!res.ok) throw new Error('network probe failed');
            return res.json();
        }).then(function (data) {
            var net = data && data.stellar_network ? String(data.stellar_network) : null;
            var key = current();
            // testnet bridges report 'testnet'; mainnet bridges report 'pubnet'.
            var ok = (key === 'mainnet' && net === 'pubnet') ||
                (key === 'testnet' && net === 'testnet') ||
                (net !== null && net === key);
            return { ok: ok, stellar_network: net };
        }).catch(function () {
            return { ok: false, stellar_network: null };
        });
    }

    /**
     * Render the selector into a container element and wire its behaviour.
     * @param {string} containerId
     */
    function mount(containerId) {
        var container = document.getElementById(containerId);
        if (!container) return;
        var cfg = config();
        if (typeof NetConfig === 'undefined' || !cfg) {
            container.innerHTML = '';
            return;
        }

        var nets = NetConfig.listNetworks(cfg);
        if (nets.length === 0) {
            container.innerHTML = '';
            return;
        }
        var cur = current();

        var html = '<span class="net-badge net-' + escapeHtml(cur) + '" id="net-indicator" title="Checking network...">' +
            '<span class="net-dot" aria-hidden="true"></span>' +
            escapeHtml((cfg.networks[cur] && cfg.networks[cur].label) || cur) +
            '</span>';
        html += '<label class="sr-only" for="net-select">Network</label>';
        html += '<select id="net-select" class="net-select" aria-label="Network">';
        nets.forEach(function (n) {
            html += '<option value="' + escapeHtml(n.key) + '"' + (n.key === cur ? ' selected' : '') + '>' +
                escapeHtml(n.label) + '</option>';
        });
        html += '</select>';
        container.innerHTML = html;

        var select = document.getElementById('net-select');
        if (select) {
            select.addEventListener('change', function () {
                switchTo(this.value);
            });
        }

        // Probe the live network and reflect it on the indicator.
        var indicator = document.getElementById('net-indicator');
        if (indicator) {
            confirmLive().then(function (result) {
                if (result.ok) {
                    indicator.classList.add('net-ok');
                    indicator.title = 'Connected to ' + (result.stellar_network || cur);
                } else {
                    indicator.classList.add('net-warn');
                    indicator.title = result.stellar_network
                        ? 'Warning: bridge reports "' + result.stellar_network + '"'
                        : 'Warning: could not reach this network';
                }
            });
        }
    }

    return {
        current: current,
        isAuthedOn: isAuthedOn,
        switchTo: switchTo,
        confirmLive: confirmLive,
        mount: mount
    };
})();

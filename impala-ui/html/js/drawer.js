/**
 * Framework-free accessible side drawer.
 *
 * Slides in from the right for detail views (e.g. the account console drawer).
 * Same accessibility contract as modal.js: role=dialog, aria-modal, focus the
 * first control, ESC + overlay-click to close, restore focus on close.
 *
 * Usage:
 *   var d = Drawer.open({ title: 'Account', bodyHtml: '<div class="skeleton"></div>' });
 *   d.setBody(renderedHtml);          // replace contents after a fetch
 *   d.body.querySelector('#x') ...    // wire controls inside the drawer
 *
 * @module Drawer
 */
var Drawer = (function () {
    var activeOverlay = null;
    var activePanel = null;
    var lastFocus = null;

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str == null ? '' : str));
        return div.innerHTML;
    }

    function focusable(container) {
        return Array.prototype.slice.call(container.querySelectorAll(
            'a[href], button:not([disabled]), textarea, input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
        ));
    }

    function onKeydown(e) {
        if (!activePanel) return;
        if (e.key === 'Escape') {
            e.preventDefault();
            close();
            return;
        }
        if (e.key === 'Tab') {
            var items = focusable(activePanel);
            if (items.length === 0) return;
            var first = items[0];
            var last = items[items.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        }
    }

    /** Close the active drawer and restore focus to the trigger. */
    function close() {
        if (!activeOverlay) return;
        document.removeEventListener('keydown', onKeydown, true);
        if (activeOverlay.parentNode) activeOverlay.parentNode.removeChild(activeOverlay);
        activeOverlay = null;
        activePanel = null;
        if (lastFocus && typeof lastFocus.focus === 'function') {
            lastFocus.focus();
        }
        lastFocus = null;
    }

    /**
     * Open a side drawer.
     * @param {Object} opts - { title, bodyHtml }
     * @returns {{ close: function, panel: HTMLElement, body: HTMLElement,
     *            setBody: function, setTitle: function, focusFirst: function }}
     */
    function open(opts) {
        opts = opts || {};
        close();
        lastFocus = document.activeElement;

        var overlay = document.createElement('div');
        overlay.className = 'overlay drawer-overlay';
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) close();
        });

        var panel = document.createElement('aside');
        panel.className = 'drawer';
        panel.setAttribute('role', 'dialog');
        panel.setAttribute('aria-modal', 'true');
        panel.setAttribute('aria-labelledby', 'drawer-title');
        panel.innerHTML =
            '<div class="drawer-header">' +
            '<h5 id="drawer-title">' + escapeHtml(opts.title || '') + '</h5>' +
            '<button type="button" class="button icon" data-drawer-close aria-label="Close">&times;</button>' +
            '</div>' +
            '<div class="drawer-body" id="drawer-body">' + (opts.bodyHtml || '') + '</div>';

        overlay.appendChild(panel);
        document.body.appendChild(overlay);
        activeOverlay = overlay;
        activePanel = panel;
        document.addEventListener('keydown', onKeydown, true);

        panel.querySelector('[data-drawer-close]').addEventListener('click', close);

        // Animate in after layout.
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(function () { panel.classList.add('open'); });
        } else {
            panel.classList.add('open');
        }

        var body = panel.querySelector('#drawer-body');
        var closeBtn = panel.querySelector('[data-drawer-close]');
        if (closeBtn) closeBtn.focus();

        function focusFirst() {
            var items = focusable(body);
            if (items.length) items[0].focus();
        }

        return {
            close: close,
            panel: panel,
            body: body,
            setBody: function (html) { body.innerHTML = html; },
            setTitle: function (t) {
                var h = panel.querySelector('#drawer-title');
                if (h) h.textContent = t == null ? '' : t;
            },
            focusFirst: focusFirst
        };
    }

    return {
        open: open,
        close: close
    };
})();

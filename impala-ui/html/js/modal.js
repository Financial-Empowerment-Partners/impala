/**
 * Framework-free accessible modal dialog.
 *
 * Mirrors the accessible overlay pattern used by session-timer.js (role=dialog,
 * aria-modal, focus the first control, ESC + overlay-click to close, restore
 * focus to the trigger) without pulling in jQuery / Foundation JS — keeping the
 * door open for a strict CSP later.
 *
 * Usage:
 *   Modal.open({ title, bodyHtml, confirmLabel, onConfirm });
 *   Modal.confirm({ title, message }).then(function (ok) { ... });
 *
 * @module Modal
 */
var Modal = (function () {
    var activeOverlay = null;
    var activeOnClose = null;
    var lastFocus = null;

    // Delegates to the shared escaper: a text-node round trip escapes & < >
    // but NOT quotes, so values interpolated into double-quoted attributes
    // (value="...", title="...") could break out and inject attributes.
    function escapeHtml(str) {
        return EscapeHtml.escape(str);
    }

    function focusable(container) {
        return Array.prototype.slice.call(container.querySelectorAll(
            'a[href], button:not([disabled]), textarea, input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
        ));
    }

    function onKeydown(e) {
        if (!activeOverlay) return;
        if (e.key === 'Escape') {
            e.preventDefault();
            close();
            return;
        }
        if (e.key === 'Tab') {
            var items = focusable(activeOverlay);
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

    /** Close the active modal, restore focus, and fire its onClose callback. */
    function close() {
        if (!activeOverlay) return;
        document.removeEventListener('keydown', onKeydown, true);
        if (activeOverlay.parentNode) activeOverlay.parentNode.removeChild(activeOverlay);
        activeOverlay = null;
        var cb = activeOnClose;
        activeOnClose = null;
        if (lastFocus && typeof lastFocus.focus === 'function') {
            lastFocus.focus();
        }
        lastFocus = null;
        if (typeof cb === 'function') cb();
    }

    /**
     * Open a modal dialog.
     * @param {Object} opts
     * @param {string}   [opts.title]
     * @param {string}   [opts.bodyHtml]      Pre-escaped HTML for the body.
     * @param {string}   [opts.confirmLabel]  Confirm button text (null to omit).
     * @param {string}   [opts.cancelLabel]   Cancel button text (null to omit).
     * @param {string}   [opts.confirmClass]  Extra class(es) for the confirm button.
     * @param {function} [opts.onConfirm]     Called with (dialog, helpers) on confirm.
     *                                        helpers = { close, button }. If omitted,
     *                                        the confirm button just closes the modal.
     * @param {function} [opts.onClose]       Called once when the modal closes by any path.
     * @returns {{ close: function, dialog: HTMLElement, confirmBtn: HTMLElement|null }}
     */
    function open(opts) {
        opts = opts || {};
        close();
        lastFocus = document.activeElement;
        activeOnClose = opts.onClose || null;

        var overlay = document.createElement('div');
        overlay.className = 'overlay';
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) close();
        });

        var dialog = document.createElement('div');
        dialog.className = 'modal';
        dialog.setAttribute('role', 'dialog');
        dialog.setAttribute('aria-modal', 'true');
        if (opts.title) dialog.setAttribute('aria-labelledby', 'modal-title');

        var html = '';
        if (opts.title) {
            html += '<h5 id="modal-title" class="modal-title">' + escapeHtml(opts.title) + '</h5>';
        }
        html += '<div class="modal-body">' + (opts.bodyHtml || '') + '</div>';
        html += '<div class="modal-actions">';
        if (opts.cancelLabel !== null) {
            html += '<button type="button" class="button ghost" data-modal-cancel>' +
                escapeHtml(opts.cancelLabel || 'Cancel') + '</button>';
        }
        if (opts.confirmLabel !== null) {
            html += '<button type="button" class="button ' + (opts.confirmClass || '') + '" data-modal-confirm>' +
                escapeHtml(opts.confirmLabel || 'Confirm') + '</button>';
        }
        html += '</div>';
        dialog.innerHTML = html;

        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        activeOverlay = overlay;
        document.addEventListener('keydown', onKeydown, true);

        var confirmBtn = dialog.querySelector('[data-modal-confirm]');
        var cancelBtn = dialog.querySelector('[data-modal-cancel]');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', close);
        }
        if (confirmBtn) {
            confirmBtn.addEventListener('click', function () {
                if (typeof opts.onConfirm === 'function') {
                    opts.onConfirm(dialog, { close: close, button: confirmBtn });
                } else {
                    close();
                }
            });
        }

        var items = focusable(dialog);
        if (items.length) {
            items[0].focus();
        } else {
            dialog.setAttribute('tabindex', '-1');
            dialog.focus();
        }

        return { close: close, dialog: dialog, confirmBtn: confirmBtn };
    }

    /**
     * Convenience confirmation dialog.
     * @param {Object} opts - { title, message, confirmLabel, cancelLabel, confirmClass }
     * @returns {Promise<boolean>} Resolves true on confirm, false on cancel/close.
     */
    function confirm(opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var confirmed = false;
            open({
                title: opts.title || 'Confirm',
                bodyHtml: '<p>' + escapeHtml(opts.message || 'Are you sure?') + '</p>',
                confirmLabel: opts.confirmLabel || 'Confirm',
                cancelLabel: opts.cancelLabel || 'Cancel',
                confirmClass: opts.confirmClass || 'alert',
                onConfirm: function (dialog, helpers) {
                    confirmed = true;
                    helpers.close();
                },
                onClose: function () {
                    resolve(confirmed);
                }
            });
        });
    }

    return {
        open: open,
        confirm: confirm,
        close: close
    };
})();

/**
 * Session idle timer module.
 *
 * Monitors user activity (click, keypress, mousemove, scroll) and:
 *  - Shows a warning modal at 13 minutes of inactivity
 *  - Auto-logs out (clears localStorage, redirects to login) at 15 minutes
 *
 * The warning modal uses ARIA attributes for accessibility.
 *
 * @module SessionTimer
 */
var SessionTimer = (function () {
    var IDLE_TIMEOUT = 15 * 60 * 1000;  // 15 minutes
    var WARNING_TIME = 13 * 60 * 1000;  // Warning at 13 minutes

    var idleTimer = null;
    var warningTimer = null;
    var modalElement = null;
    var activityEvents = ['click', 'keypress', 'mousemove', 'scroll'];
    var initialized = false;

    /** Activity handler — resets both timers. */
    function onActivity() {
        hideWarning();
        startTimers();
    }

    /** Start (or restart) the idle and warning timers. */
    function startTimers() {
        clearTimeout(warningTimer);
        clearTimeout(idleTimer);

        warningTimer = setTimeout(function () {
            showWarning();
        }, WARNING_TIME);

        idleTimer = setTimeout(function () {
            doLogout();
        }, IDLE_TIMEOUT);
    }

    /** Create and show the session expiry warning modal. */
    function showWarning() {
        if (modalElement) return; // already showing

        var overlay = document.createElement('div');
        overlay.id = 'session-warning-overlay';
        overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:10000;display:flex;align-items:center;justify-content:center;';

        var modal = document.createElement('div');
        modal.setAttribute('role', 'alertdialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'session-warning-title');
        modal.setAttribute('aria-describedby', 'session-warning-desc');
        // Styled via app.css tokens (not a hardcoded #fff) so the dialog stays
        // legible in dark mode — text inherits var(--text), and this is the
        // one dialog that races a forced logout.
        modal.style.cssText = 'background:var(--surface);color:var(--text);border:1px solid var(--border);box-shadow:var(--shadow-lg);padding:2rem;border-radius:4px;max-width:420px;width:90%;text-align:center;';

        modal.innerHTML =
            '<h5 id="session-warning-title">Session Expiring</h5>' +
            '<p id="session-warning-desc">Your session will expire in 2 minutes due to inactivity.</p>' +
            '<div style="display:flex;gap:1rem;justify-content:center;margin-top:1rem;">' +
            '<button class="button" id="session-stay-btn">Stay Logged In</button>' +
            '<button class="button alert" id="session-logout-btn">Log Out</button>' +
            '</div>';

        overlay.appendChild(modal);
        document.body.appendChild(overlay);
        modalElement = overlay;

        var stayBtn = document.getElementById('session-stay-btn');
        var logoutBtn = document.getElementById('session-logout-btn');

        stayBtn.addEventListener('click', function () {
            hideWarning();
            startTimers();
        });
        stayBtn.focus();

        logoutBtn.addEventListener('click', function () {
            doLogout();
        });
    }

    /** Hide the warning modal if it is showing. */
    function hideWarning() {
        if (modalElement && modalElement.parentNode) {
            modalElement.parentNode.removeChild(modalElement);
        }
        modalElement = null;
    }

    /** End the session (revoking server-side) and redirect to the login page. */
    function doLogout() {
        stop();
        if (typeof Auth !== 'undefined' && Auth.logout) {
            Auth.logout();
            return;
        }
        // Fallback: drop the active network's tokens and bounce to login.
        if (typeof API !== 'undefined' && typeof API.clearTokens === 'function') {
            API.clearTokens();
        }
        window.location.href = 'index.html';
    }

    /**
     * Initialize the session timer. Sets up activity listeners and starts timers.
     * Safe to call multiple times — only initializes once.
     */
    function init() {
        if (initialized) return;
        initialized = true;

        for (var i = 0; i < activityEvents.length; i++) {
            document.addEventListener(activityEvents[i], onActivity, { passive: true });
        }
        startTimers();
    }

    /** Reset the idle timer (e.g. after an API call). */
    function reset() {
        if (initialized) {
            hideWarning();
            startTimers();
        }
    }

    /** Stop all timers and remove event listeners. */
    function stop() {
        clearTimeout(warningTimer);
        clearTimeout(idleTimer);
        hideWarning();

        for (var i = 0; i < activityEvents.length; i++) {
            document.removeEventListener(activityEvents[i], onActivity);
        }
        initialized = false;
    }

    return {
        init: init,
        reset: reset,
        stop: stop
    };
})();

/**
 * Okta callback page entry point.
 *
 * Lives in its own file (rather than inline in okta-callback.html) so the
 * CSP can stay `script-src 'self'` with no 'unsafe-inline'.
 */
OktaAuth.handleCallback();

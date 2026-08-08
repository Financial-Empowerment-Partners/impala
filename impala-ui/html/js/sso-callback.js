/**
 * Multi-provider SSO callback page entry point.
 *
 * Lives in its own file (rather than inline in sso-callback.html) so the
 * CSP can stay `script-src 'self'` with no 'unsafe-inline'. The inline
 * version this replaces was silently blocked by that CSP, which left the
 * whole SSO callback path dead on arrival.
 */
SsoAuth.handleCallback();

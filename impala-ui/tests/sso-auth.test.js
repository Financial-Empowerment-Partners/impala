import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

let SsoAuth;
beforeAll(() => {
    SsoAuth = loadScript('sso-auth.js', 'SsoAuth');
});

describe('SsoAuth.isAllowedTokenEndpoint', () => {
    it('allows HTTPS endpoints on any host', () => {
        expect(SsoAuth.isAllowedTokenEndpoint('https://your-org.okta.com/oauth2/v1/token')).toBe(true);
        expect(SsoAuth.isAllowedTokenEndpoint('https://idp.example.com:8443/token')).toBe(true);
    });

    it('allows plain HTTP on loopback hosts (local dev IdPs)', () => {
        expect(SsoAuth.isAllowedTokenEndpoint('http://localhost:8200/v1/identity/oidc/provider/openbao/token')).toBe(true);
        expect(SsoAuth.isAllowedTokenEndpoint('http://127.0.0.1:8200/token')).toBe(true);
        expect(SsoAuth.isAllowedTokenEndpoint('http://[::1]:8200/token')).toBe(true);
    });

    it('rejects plain HTTP on non-loopback hosts', () => {
        expect(SsoAuth.isAllowedTokenEndpoint('http://idp.example.com/token')).toBe(false);
        expect(SsoAuth.isAllowedTokenEndpoint('http://intranet:8200/token')).toBe(false);
        expect(SsoAuth.isAllowedTokenEndpoint('http://localhost.evil.com/token')).toBe(false);
    });

    it('rejects userinfo tricks that spoof a loopback host', () => {
        expect(SsoAuth.isAllowedTokenEndpoint('http://localhost@evil.com/token')).toBe(false);
        expect(SsoAuth.isAllowedTokenEndpoint('http://127.0.0.1:pass@evil.com/token')).toBe(false);
    });

    it('rejects non-HTTP(S) schemes', () => {
        expect(SsoAuth.isAllowedTokenEndpoint('ftp://localhost/token')).toBe(false);
        expect(SsoAuth.isAllowedTokenEndpoint('javascript:alert(1)')).toBe(false);
    });

    it('rejects unparseable values', () => {
        expect(SsoAuth.isAllowedTokenEndpoint('')).toBe(false);
        expect(SsoAuth.isAllowedTokenEndpoint('not a url')).toBe(false);
        expect(SsoAuth.isAllowedTokenEndpoint('//localhost:8200/token')).toBe(false);
    });
});

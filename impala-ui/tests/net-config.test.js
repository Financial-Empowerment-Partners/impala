import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

let NetConfig;
beforeAll(() => {
    NetConfig = loadScript('net-config.js', 'NetConfig');
});

const cfg = {
    networks: {
        testnet: { base: '/api/testnet', label: 'Testnet' },
        mainnet: { base: '/api/mainnet', label: 'Mainnet' }
    },
    default: 'testnet'
};

describe('NetConfig.resolveKey', () => {
    it('prefers a valid selected key', () => {
        expect(NetConfig.resolveKey(cfg, 'mainnet')).toBe('mainnet');
    });

    it('falls back to the default for an unknown selection', () => {
        expect(NetConfig.resolveKey(cfg, 'bogus')).toBe('testnet');
    });

    it('falls back to the default when nothing is selected', () => {
        expect(NetConfig.resolveKey(cfg, null)).toBe('testnet');
    });

    it('falls back to the first network when default is invalid', () => {
        const noDefault = { networks: cfg.networks, default: 'nope' };
        expect(NetConfig.resolveKey(noDefault, null)).toBe('testnet');
    });

    it('returns null when there are no networks', () => {
        expect(NetConfig.resolveKey(null, 'x')).toBe(null);
        expect(NetConfig.resolveKey({ networks: {} }, null)).toBe(null);
    });
});

describe('NetConfig.resolveBase', () => {
    it('resolves the base for the selected network', () => {
        expect(NetConfig.resolveBase(cfg, 'mainnet')).toBe('/api/mainnet');
    });

    it('resolves the default base when nothing is selected', () => {
        expect(NetConfig.resolveBase(cfg, null)).toBe('/api/testnet');
    });

    it('returns a safe fallback when unresolvable', () => {
        expect(NetConfig.resolveBase(null, null)).toBe('/api');
        expect(NetConfig.resolveBase({ networks: {} }, null)).toBe('/api');
    });
});

describe('NetConfig.listNetworks', () => {
    it('lists configured networks with key/label/base', () => {
        const nets = NetConfig.listNetworks(cfg);
        expect(nets).toHaveLength(2);
        expect(nets[0]).toEqual({ key: 'testnet', label: 'Testnet', base: '/api/testnet' });
        expect(nets.map((n) => n.key)).toContain('mainnet');
    });

    it('returns an empty array for missing config', () => {
        expect(NetConfig.listNetworks(null)).toEqual([]);
        expect(NetConfig.listNetworks({})).toEqual([]);
    });
});

describe('NetConfig.tokenKey', () => {
    it('namespaces a token name by network', () => {
        expect(NetConfig.tokenKey('temporal_token', 'mainnet')).toBe('temporal_token::mainnet');
        expect(NetConfig.tokenKey('refresh_token', 'testnet')).toBe('refresh_token::testnet');
    });

    it('returns the bare name without a network key', () => {
        expect(NetConfig.tokenKey('temporal_token', null)).toBe('temporal_token');
        expect(NetConfig.tokenKey('temporal_token', '')).toBe('temporal_token');
    });
});

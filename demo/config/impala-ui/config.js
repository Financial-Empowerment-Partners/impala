/**
 * demo/ override of impala-ui/html/config.js: testnet only.
 * The demo runs a single bridge on Stellar testnet; the upstream file also lists "mainnet", which
 * would silently route to the same testnet bridge through the mainnet-bridge network alias.
 */
window.IMPALA_CONFIG = {
    networks: {
        testnet: { base: '/api/testnet', label: 'Testnet' }
    },
    default: 'testnet'
};

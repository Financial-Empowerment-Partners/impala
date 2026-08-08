import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        // Both directories: `test/` predates `tests/` and its files — including
        // the escape-html XSS suite and the api-csrf suite — were silently
        // never executed while the pattern matched only `tests/`.
        include: ['tests/**/*.test.js', 'test/**/*.test.js'],
        environment: 'node',
        globals: false,
        reporters: ['default'],
    },
});

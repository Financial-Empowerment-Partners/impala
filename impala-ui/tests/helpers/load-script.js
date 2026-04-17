import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const uiRoot = resolve(here, '..', '..');

/**
 * Load a vanilla-JS IIFE module from `html/js/` and return the named global
 * it exposes.
 *
 * Example: `loadScript('validate.js', 'Validate')` reads
 * `impala-ui/html/js/validate.js`, wraps it in a function scope, and returns
 * the `Validate` symbol it declares.
 */
export function loadScript(filename, exportName) {
    const src = readFileSync(resolve(uiRoot, 'html', 'js', filename), 'utf8');
    // eslint-disable-next-line no-new-func
    const factory = new Function(`${src}\nreturn ${exportName};`);
    return factory();
}

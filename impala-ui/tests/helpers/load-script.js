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

/**
 * Load several IIFE modules into ONE function scope, in the given order (the
 * same order as their <script> tags), and return the named globals.
 *
 * Example: `loadScripts(['validate.js', 'cards-view.js'], ['Validate', 'CardsView'])`.
 */
export function loadScripts(filenames, exportNames) {
    const src = filenames
        .map((f) => readFileSync(resolve(uiRoot, 'html', 'js', f), 'utf8'))
        .join('\n;\n');
    // eslint-disable-next-line no-new-func
    const factory = new Function(`${src}\nreturn { ${exportNames.join(', ')} };`);
    return factory();
}

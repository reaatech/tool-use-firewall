import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'tsup';

const pkg = JSON.parse(readFileSync(resolve('package.json'), 'utf-8')) as {
  version: string;
};

const define = {
  __PACKAGE_VERSION__: JSON.stringify(pkg.version),
};

export default defineConfig([
  // Library entry — dual CJS/ESM for programmatic consumers.
  {
    entry: { index: 'src/index.ts' },
    format: ['cjs', 'esm'],
    dts: { resolve: true },
    clean: true,
    tsconfig: './tsconfig.json',
    define,
  },
  // CLI entry — ESM-only. It uses `import.meta.url` to detect the main module,
  // which is invalid in CJS; the `bin` field points at the ESM output only.
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    dts: { resolve: true },
    clean: false,
    tsconfig: './tsconfig.json',
    define,
  },
]);

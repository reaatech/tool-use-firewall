import { defineConfig } from 'tsup';

export default defineConfig([
  // Library entry — dual CJS/ESM re-export of the server package.
  {
    entry: { index: 'src/index.ts' },
    format: ['cjs', 'esm'],
    dts: { resolve: true },
    clean: true,
    tsconfig: './tsconfig.json',
  },
  // CLI entry — ESM-only launcher (matches the server CLI, which is ESM-only).
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    dts: { resolve: true },
    clean: false,
    tsconfig: './tsconfig.json',
  },
]);

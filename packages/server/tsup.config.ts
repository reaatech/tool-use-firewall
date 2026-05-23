import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'tsup';

const pkg = JSON.parse(readFileSync(resolve('package.json'), 'utf-8')) as {
  version: string;
};

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    cli: 'src/cli.ts',
  },
  format: ['cjs', 'esm'],
  dts: {
    resolve: true,
  },
  clean: true,
  tsconfig: './tsconfig.json',
  define: {
    __PACKAGE_VERSION__: JSON.stringify(pkg.version),
  },
});

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    pool: 'forks',
    coverage: {
      reporter: ['text', 'json-summary'],
      thresholds: {
        statements: 25,
        branches: 30,
        functions: 40,
        lines: 25,
      },
    },
  },
});

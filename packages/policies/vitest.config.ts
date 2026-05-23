import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    pool: 'forks',
    coverage: {
      reporter: ['text', 'json-summary'],
      thresholds: {
        statements: 55,
        branches: 50,
        functions: 85,
        lines: 55,
      },
    },
  },
});

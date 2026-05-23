import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    pool: 'forks',
    coverage: {
      reporter: ['text', 'json-summary'],
      thresholds: {
        statements: 20,
        branches: 80,
        functions: 60,
        lines: 20,
      },
    },
  },
});

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      thresholds: {
        global: {
          statements: 90,
          branches: 90,
          functions: 90,
          lines: 90,
        },
      },
      exclude: [
        'src/**/*.test.ts',
        // Barrel file — contains only re-exports
        'src/index.ts',
        // Process entry point — calls process.exit() and is tested via integration tests
        'src/cli.ts',
        // Core proxy server — extensively tested via integration tests (tests/integration/proxy.test.ts)
        // Unit testing requires mocking child_process, process.stdin/stdout which provides limited value
        'src/server.ts',
        'tests/fixtures/**',
        'dist/**',
        'node_modules/**',
      ],
    },
  },
});

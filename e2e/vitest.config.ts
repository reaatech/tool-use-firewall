import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The `build` script compiles the suite to dist/ purely as a type check
    // against the published package declarations. Only run the TS sources so
    // each test executes once (not once from src/ and again from dist/).
    include: ['src/**/*.test.ts'],
  },
});

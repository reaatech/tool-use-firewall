# Skill: Project Setup

## Description
Initialize and configure the tool-use-firewall project with proper TypeScript, testing, and linting setup.

## When to Use
- Starting a new development session
- Setting up the project for the first time
- Resetting project configuration

## Capabilities
- Initialize pnpm project with correct metadata
- Configure TypeScript with strict mode
- Set up ESLint and Prettier
- Configure Vitest with coverage thresholds
- Set up Husky pre-commit hooks
- Create directory structure

## Usage

### Initialize Project
```bash
pnpm init
pnpm add typescript @types/node tsx
pnpm add -D vitest @vitest/coverage-v8 eslint prettier husky lint-staged
```

### Configure TypeScript
Create `tsconfig.json` with:
- `strict: true`
- `module: "NodeNext"`
- `target: "ES2022"`
- `moduleResolution: "NodeNext"`

### Configure Testing
Create `vitest.config.ts` with:
- Coverage threshold of 90%
- Include `src/**/*.ts`
- Exclude `src/**/*.test.ts` from coverage input

### Configure Linting
Create `.eslintrc.json` with:
- `@typescript-eslint/recommended`
- `prettier` plugin
- Strict rules for security

### Set Up Pre-commit Hooks
```bash
npx husky init
```

Add to `.husky/pre-commit`:
```bash
npx lint-staged
```

## Output
- Fully configured TypeScript project
- Test suite ready with coverage tracking
- Pre-commit hooks for code quality
- Proper directory structure

## Related Skills
- `testing` - Write and run tests
- `security-review` - Security-focused code review

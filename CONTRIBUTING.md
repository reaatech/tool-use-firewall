# Contributing to tool-use-firewall

Thank you for your interest in contributing to **tool-use-firewall**! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and constructive in your interactions. We are committed to providing a welcoming and inclusive experience for everyone.

## Getting Started

### Prerequisites

- Node.js 20+ (LTS)
- pnpm 9+
- Git

### Setting Up the Development Environment

1. **Fork the repository**

   Click the "Fork" button on GitHub to create your own copy of the repository.

2. **Clone the repository**

   ```bash
   git clone https://github.com/reaatech/tool-use-firewall.git
   cd tool-use-firewall
   ```

3. **Install dependencies**

   ```bash
   pnpm install
   ```

4. **Set up pre-commit hooks**

   ```bash
   pnpm run prepare
   ```

5. **Run tests to verify setup**

   ```bash
   pnpm test
   ```

## Development Workflow

### Branch Naming

Use descriptive branch names:

- `feat/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring
- `test/description` - Test additions or modifications
- `chore/description` - Maintenance tasks

### Making Changes

1. **Create a branch**

   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes**

   Follow the project's coding standards:
   - Use TypeScript strict mode
   - Write tests for new functionality
   - Maintain ≥90% test coverage
   - Add JSDoc comments for public APIs
   - Keep functions small and focused (≤25 lines preferred)

3. **Run tests**

   ```bash
   pnpm test
   ```

4. **Check code quality**

   ```bash
   pnpm run lint
   pnpm run format:check
   ```

5. **Commit your changes**

   Write clear, concise commit messages:

   ```bash
   git commit -m "feat: add SQL injection pattern detection"
   ```

   Follow [Conventional Commits](https://www.conventionalcommits.org/) format:
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation
   - `refactor:` - Code refactoring
   - `test:` - Tests
   - `chore:` - Maintenance

6. **Push to your fork**

   ```bash
   git push origin feat/your-feature-name
   ```

### Opening a Pull Request

1. **Go to the original repository** on GitHub

2. **Click "New Pull Request"**

3. **Select your branch** as the compare branch

4. **Fill out the PR template** with:
   - Description of changes
   - Related issues (if any)
   - Testing done
   - Checklist items

5. **Wait for review**

   Maintainers will review your PR and may request changes.

## Coding Standards

### TypeScript

- Use strict mode (`strict: true`)
- Avoid `any` types without explicit justification
- Use meaningful variable and function names
- Prefer `const` over `let`
- Use async/await for asynchronous code

### Testing

- Write tests alongside implementation
- Maintain ≥90% code coverage
- Use descriptive test names
- Test both happy paths and error cases
- Include security-focused test cases

### Documentation

- Add JSDoc comments for public APIs
- Update README.md if user-facing changes
- Update ARCHITECTURE.md if architecture changes
- Add inline comments for complex logic

### Security

- Never bypass validation or policy checks
- Don't log sensitive data
- Don't expose internal details in error messages
- Follow the principle of least privilege

## Types of Contributions

### Bug Fixes

Bug fixes are always welcome! Please:
- Describe the bug clearly
- Include steps to reproduce
- Add a test case that fails before the fix
- Reference any related issues

### New Features

New features should:
- Align with the project's goals
- Include comprehensive tests
- Update documentation
- Be discussed in an issue first (for major features)

### Documentation

Documentation improvements are highly valued:
- Fix typos or unclear explanations
- Add examples
- Improve API documentation
- Add troubleshooting guides

### Performance Improvements

Performance improvements should:
- Include benchmarks showing improvement
- Not sacrifice security or correctness
- Be well-documented

## Reporting Issues

### Bug Reports

When reporting a bug, please include:
- Clear description of the issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (Node.js version, OS, etc.)
- Screenshots or logs if helpful

### Security Issues

**Do not report security vulnerabilities in public issues.**

Please report security issues privately to:
- GitHub Security Advisories: https://github.com/reaatech/tool-use-firewall/security/advisories
- Email: security@reaatech.com (if available)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

### Feature Requests

Feature requests are welcome! Please:
- Describe the feature clearly
- Explain the use case
- Provide examples if possible
- Be open to feedback and discussion

## Review Process

### What Maintainers Look For

- Code quality and correctness
- Test coverage
- Documentation completeness
- Security implications
- Performance impact
- Alignment with project goals

### Review Timeline

- We aim to review PRs within 1 week
- Complex PRs may take longer
- Please be patient and responsive to feedback

### Getting Merged

Your PR will be merged when:
- All tests pass
- Code review is approved
- All requested changes are addressed
- CI/CD checks pass

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- MAJOR.MINOR.PATCH
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### Release Schedule

- Patch releases: As needed for critical fixes
- Minor releases: Monthly or as features are ready
- Major releases: As needed for breaking changes

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).

## Questions?

If you have questions, please:
- Check existing documentation
- Search existing issues
- Ask in GitHub Discussions
- Contact maintainers

Thank you for contributing to tool-use-firewall! 🎉

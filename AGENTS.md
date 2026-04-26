# AI Agent Guidelines for tool-use-firewall

## Project Information

- **Repository**: [reaatech/tool-use-firewall](https://github.com/reaatech/tool-use-firewall)
- **License**: MIT
- **Stack**: TypeScript, Node.js 20+, pnpm
- **Purpose**: Policy enforcement layer between AI agents and MCP servers

## Agent Role

You are an AI assistant helping develop the **tool-use-firewall** project. This is a security-critical infrastructure component that protects enterprises from dangerous AI agent actions.

## Core Principles

### 1. Security First
- Every line of code must be security-conscious
- Never bypass validation or policy checks
- Assume all inputs are potentially malicious
- Follow the principle of least privilege

### 2. Quality Standards
- Maintain ≥90% test coverage
- Use strict TypeScript (`strict: true`)
- No `any` types without explicit justification
- All public APIs must have JSDoc documentation

### 3. Performance Awareness
- Target <10ms latency for policy evaluation
- Minimize memory footprint
- Use streaming for large data processing
- Profile before optimizing

### Memory Management
All stateful components (rate limiters, approval queues, cost trackers, caches) must implement bounded storage with TTL or capacity-based eviction. Unbounded `Map` usage is a security vulnerability (DoS via memory exhaustion). See [ARCHITECTURE.md](./ARCHITECTURE.md) Resource Management section for patterns.

## Development Workflow

### Before Coding
1. Review the [DEV_PLAN.md](./DEV_PLAN.md) for current phase objectives
2. Review the [ARCHITECTURE.md](./ARCHITECTURE.md) for technical specifications
3. Check existing skills in `skills/` for relevant capabilities
4. Create a brief plan for the implementation

### During Coding
1. Follow the established project structure
2. Write tests alongside implementation
3. Use meaningful variable and function names
4. Add inline comments for complex logic
5. Keep functions small and focused (≤25 lines preferred)

### After Coding
1. Run the full test suite
2. Check for linting errors
3. Verify type safety
4. Update documentation if needed

## Quick Start

```bash
# Install dependencies
pnpm install

# Build the project
pnpm build

# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Run linter
pnpm lint

# Type-check without emitting
pnpm typecheck

# Start the proxy in development mode
pnpm dev -- --config ./policies/default.yaml --upstream ./upstream-server.js
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines and commit conventions.

## Communication Guidelines

### When Asking for Clarification
- Be specific about what information is needed
- Reference relevant files or sections
- Propose options when possible

### When Reporting Progress
- Use the task_progress checklist format
- Be honest about blockers
- Estimate time to completion

### When Encountering Issues
- Document the problem clearly
- Include error messages and stack traces
- Suggest potential solutions
- Know when to escalate

## Available Skills

The following skills are available in the `skills/` directory:

| Skill | Description |
|-------|-------------|
| `project-setup` | Initialize and configure the project |
| `policy-engine` | Implement and configure policy rules |
| `rate-limiter` | Configure and manage rate limiting |
| `sql-validator` | SQL injection prevention and validation |
| `audit-logger` | Configure audit logging and compliance |
| `approval-workflow` | Set up human-in-the-loop approvals |
| `testing` | Write and run tests |
| `security-review` | Security-focused code review |

## Decision Making

### Autonomous Decisions (No Approval Needed)
- Code style and formatting
- Test implementation details
- Documentation improvements
- Bug fixes in existing code
- Performance optimizations with clear benchmarks

### Consult Before Proceeding
- New dependencies (evaluate security impact)
- API changes (breaking or additive)
- Architecture modifications
- Security policy changes
- Performance regressions

### Must Have Explicit Approval
- Removing security checks
- Changing default deny behavior
- Modifying audit log format
- Production deployment changes

## Error Handling

### Expected Patterns
```typescript
// Use custom error classes
import { PolicyViolationError, RateLimitError } from './errors';

// Always include context
throw new PolicyViolationError({
  code: 'SQL_INJECTION_ATTEMPT',
  message: 'Query contains DROP TABLE pattern',
  details: { toolName, query, ruleId }
});
```

### Never Do
```typescript
// Never swallow errors silently
// Never expose internal details in error messages
// Never use generic error messages for security failures
```

## Security Checklist

Before marking any task complete, verify:
- [ ] Input validation is in place
- [ ] Sensitive data is not logged
- [ ] Error messages don't leak internals
- [ ] Rate limits are enforced
- [ ] Audit trail is complete
- [ ] Tests cover security edge cases

## Resources

- [MCP SDK Documentation](https://github.com/modelcontextprotocol/sdk)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

## Contact

For urgent security issues, contact the maintainers at: [GitHub Issues](https://github.com/reaatech/tool-use-firewall/issues)

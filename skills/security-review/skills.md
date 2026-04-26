# Skill: Security Review

## Description
Perform security-focused code review for the tool-use-firewall project. This skill provides systematic security analysis, vulnerability detection, and compliance verification to ensure the firewall meets enterprise security standards.

## When to Use
- Before merging security-critical changes
- Periodic security audits
- After implementing new validation rules
- Before production deployments
- When responding to security incidents

## Capabilities
- Static security analysis
- Input validation review
- Authentication/authorization review
- Audit trail verification
- Dependency vulnerability scanning
- OWASP compliance checking
- Threat modeling

## Security Review Checklist

### 1. Input Validation
- [ ] All user inputs are validated before use
- [ ] SQL injection patterns are blocked
- [ ] Command injection vectors are eliminated
- [ ] Path traversal is prevented
- [ ] XSS vectors are sanitized (if applicable)
- [ ] Type validation is enforced
- [ ] Length limits are enforced
- [ ] Encoding/escaping is applied where needed

### 2. Authentication & Authorization
- [ ] Authentication tokens are validated
- [ ] Session management is secure
- [ ] Authorization checks are enforced
- [ ] Privilege escalation is prevented
- [ ] API keys are handled securely

### 3. Data Protection
- [ ] Sensitive data is not logged
- [ ] Secrets are stored in environment variables
- [ ] Encryption is used for sensitive data in transit
- [ ] PII is redacted in logs
- [ ] Memory is cleared after use (for sensitive data)

### 4. Audit & Logging
- [ ] All security events are logged
- [ ] Logs include sufficient context
- [ ] Log integrity is protected
- [ ] Log retention is configured
- [ ] Audit trail is complete

### 5. Error Handling
- [ ] Errors don't leak internal details
- [ ] Stack traces are not exposed
- [ ] Error messages are generic
- [ ] Fail-secure behavior is implemented
- [ ] Error conditions are logged

### 6. Rate Limiting & DoS Prevention
- [ ] Rate limits are enforced
- [ ] Resource limits are set
- [ ] Timeout values are configured
- [ ] Memory limits are enforced
- [ ] CPU limits are considered

### 7. Dependencies
- [ ] Dependencies are up-to-date
- [ ] Known vulnerabilities are addressed
- [ ] Dependencies are from trusted sources
- [ ] License compliance is verified
- [ ] Supply chain risks are assessed

## Security Review Process

### Phase 1: Automated Analysis
```bash
# Run security linting
pnpm run lint:security

# Check for known vulnerabilities
pnpm audit

# Run SAST tools
pnpm run security:scan

# Check dependencies
pnpm run deps:check
```

### Phase 2: Manual Code Review

#### Input Validation Review
```typescript
// Review checklist for input validation
// 1. Is the input type checked?
// 2. Is the input length validated?
// 3. Are special characters handled?
// 4. Is the input sanitized?
// 5. Is the input validated against a schema?

// Example: Good input validation
function validateQuery(query: unknown): string {
  if (typeof query !== 'string') {
    throw new ValidationError('Query must be a string');
  }
  
  if (query.length > 10000) {
    throw new ValidationError('Query too long');
  }
  
  if (containsDangerousPatterns(query)) {
    throw new ValidationError('Query contains dangerous patterns');
  }
  
  return query;
}
```

#### SQL Injection Review
```typescript
// Review checklist for SQL injection
// 1. Are parameterized queries used?
// 2. Are ORM methods used instead of raw SQL?
// 3. Are input values escaped?
// 4. Are stored procedures used?
// 5. Are database permissions restricted?

// Example: Dangerous code
const query = `SELECT * FROM users WHERE id = ${userId}`; // BAD!

// Example: Safe code
const query = 'SELECT * FROM users WHERE id = ?';
const params = [userId];
```

#### Command Injection Review
```typescript
// Review checklist for command injection
// 1. Are shell commands avoided?
// 2. If shell commands are needed, are they sanitized?
// 3. Are arguments passed as arrays?
// 4. Are dangerous characters filtered?
// 5. Is the principle of least privilege followed?

// Example: Dangerous code
exec(`ls ${userInput}`); // BAD!

// Example: Safe code
execFile('ls', [userInput]); // GOOD
```

### Phase 3: Threat Modeling

#### STRIDE Analysis
| Threat | Questions | Mitigations |
|--------|-----------|-------------|
| **S**poofing | Can an attacker impersonate a user? | Authentication, session management |
| **T**ampering | Can an attacker modify data? | Integrity checks, validation |
| **R**epudiation | Can an attacker deny actions? | Audit logging, non-repudiation |
| **I**nformation Disclosure | Can an attacker access sensitive data? | Encryption, access control |
| **D**enial of Service | Can an attacker disrupt service? | Rate limiting, resource limits |
| **E**levation of Privilege | Can an attacker gain more access? | Authorization, least privilege |

### Phase 4: Security Testing

#### SQL Injection Testing
```typescript
// Test cases for SQL injection
const injectionTests = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  "1; SELECT * FROM passwords",
  "UNION SELECT * FROM users",
  "1 AND 1=1",
  "1 AND 1=2",
  "admin'--",
  "1; WAITFOR DELAY '0:0:10'",
];

for (const injection of injectionTests) {
  const result = await validator.validate(injection);
  expect(result.valid).toBe(false);
}
```

#### Rate Limit Bypass Testing
```typescript
// Test cases for rate limit bypass
const bypassTests = [
  // Rapid-fire requests
  Array(1000).fill(null).map(() => makeRequest()),
  
  // Distributed requests (simulated)
  Array(100).fill(null).map(() => 
    makeRequest({ sessionId: generateRandomId() })
  ),
  
  // Burst requests
  Promise.all(Array(100).fill(null).map(() => makeRequest())),
];
```

## Security Review Report Template

```markdown
# Security Review Report

## Summary
- **Date**: YYYY-MM-DD
- **Reviewer**: [Name]
- **Scope**: [Components reviewed]
- **Overall Risk**: [Low/Medium/High/Critical]

## Findings

### Critical Issues (0)
| ID | Description | Location | Status |
|----|-------------|----------|--------|
| C-001 | [Description] | [File:Line] | [Open/Closed] |

### High Issues (0)
| ID | Description | Location | Status |
|----|-------------|----------|--------|
| H-001 | [Description] | [File:Line] | [Open/Closed] |

### Medium Issues (0)
| ID | Description | Location | Status |
|----|-------------|----------|--------|
| M-001 | [Description] | [File:Line] | [Open/Closed] |

### Low Issues (0)
| ID | Description | Location | Status |
|----|-------------|----------|--------|
| L-001 | [Description] | [File:Line] | [Open/Closed] |

## Recommendations
1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]

## Sign-off
- [ ] Security review completed
- [ ] All critical issues resolved
- [ ] All high issues resolved or accepted
- [ ] Medium and low issues tracked
```

## Automated Security Tools

### ESLint Security Plugin
```javascript
// .eslintrc.json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-fs-filename": "warn",
    "security/detect-eval-with-expression": "error",
    "security/detect-no-csrf-before-method-override": "error",
    "security/detect-possible-timing-attacks": "warn",
    "security/detect-unsafe-regex": "error"
  }
}
```

### Dependency Audit
```bash
# Add to package.json scripts
{
  "scripts": {
    "security:audit": "pnpm audit --audit-level high",
    "security:deps": "pnpm list --depth 0",
    "security:scan": "npx audit-ci --moderate"
  }
}
```

## Common Security Issues to Check

### 1. SQL Injection
```typescript
// ❌ BAD: String concatenation
const query = `SELECT * FROM users WHERE id = ${id}`;

// ✅ GOOD: Parameterized query
const query = 'SELECT * FROM users WHERE id = ?';
```

### 2. Command Injection
```typescript
// ❌ BAD: Unsanitized input
exec(`ping ${host}`);

// ✅ GOOD: Sanitized input
execFile('ping', [host]);
```

### 3. Path Traversal
```typescript
// ❌ BAD: No path validation
const filePath = path.join(baseDir, userInput);

// ✅ GOOD: Path validation
const safePath = path.normalize(userInput);
if (!safePath.startsWith(baseDir)) {
  throw new Error('Path traversal detected');
}
```

### 4. Information Disclosure
```typescript
// ❌ BAD: Exposing internal errors
catch (error) {
  res.status(500).json({ error: error.stack });
}

// ✅ GOOD: Generic error message
catch (error) {
  logger.error('Internal error', { error: error.message });
  res.status(500).json({ error: 'Internal server error' });
}
```

### 5. Sensitive Data in Logs
```typescript
// ❌ BAD: Logging sensitive data
logger.info('User login', { password: user.password });

// ✅ GOOD: Redacted logging
logger.info('User login', { 
  userId: user.id, 
  password: '[REDACTED]' 
});
```

## Output
- Comprehensive security review report
- List of identified vulnerabilities
- Risk assessment for each finding
- Remediation recommendations
- Sign-off documentation

## Related Skills
- `testing` - Security-focused test cases
- `audit-logger` - Verify audit trail completeness
- `sql-validator` - Review SQL injection prevention

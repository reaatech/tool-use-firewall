# Skill: SQL Validator

## Description
SQL injection prevention and validation for database tool calls. This skill implements comprehensive SQL safety checks to prevent destructive operations and SQL injection attacks.

## When to Use
- Validating SQL queries before execution
- Preventing SQL injection attacks
- Blocking destructive operations (DROP, DELETE without WHERE, TRUNCATE)
- Enforcing read-only mode for database operations

## Capabilities
- SQL injection pattern detection
- Destructive operation blocking
- WHERE clause validation
- Table/column name sanitization
- Query type classification
- Read-only mode enforcement

## SQL Safety Configuration

```yaml
# policy.yaml
sql_validation:
  # Block these patterns entirely
  blocked_patterns:
    - pattern: "DROP\\s+TABLE"
      flags: "i"
      message: "DROP TABLE is not allowed"
      
    - pattern: "TRUNCATE\\s+TABLE"
      flags: "i"
      message: "TRUNCATE is not allowed"
      
    - pattern: "DROP\\s+DATABASE"
      flags: "i"
      message: "DROP DATABASE is not allowed"
      
    - pattern: "CREATE\\s+(OR\\s+REPLACE\\s+)?(FUNCTION|PROCEDURE|TRIGGER)"
      flags: "i"
      message: "Creating database objects is not allowed"
  
  # Require WHERE clause for these operations
  require_where_clause:
    - "DELETE"
    - "UPDATE"
    
  # Allow only these statement types in read-only mode
  read_only_statements:
    - "SELECT"
    - "SHOW"
    - "DESCRIBE"
    - "EXPLAIN"
    
  # Additional injection patterns
  injection_patterns:
    - pattern: "UNION\\s+(ALL\\s+)?SELECT"
      flags: "i"
      message: "UNION SELECT is not allowed"
      
    - pattern: ";\\s*(DROP|DELETE|TRUNCATE|ALTER|CREATE)"
      flags: "i"
      message: "Multiple statements not allowed"
      
    - pattern: "OR\\s+1\\s*=\\s*1"
      flags: "i"
      message: "Tautology-based injection detected"
      
    - pattern: "'\\s*OR\\s+'"
      flags: "i"
      message: "String-based injection detected"
```

## Implementation

### SQL Validator
```typescript
// src/policies/sql-validator.ts
export interface SQLValidationResult {
  valid: boolean;
  reason?: string;
  queryType?: string;
  hasWhereClause?: boolean;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export class SQLValidator {
  private blockedPatterns: CompiledPattern[] = [];
  private injectionPatterns: CompiledPattern[] = [];
  private requireWhereClauseStatements: string[] = [];
  private readOnlyStatements: string[] = [];

  constructor(config: SQLValidationConfig) {
    this.blockedPatterns = config.blocked_patterns.map(p => ({
      ...p,
      regex: new RegExp(p.pattern, p.flags)
    }));
    
    this.injectionPatterns = config.injection_patterns.map(p => ({
      ...p,
      regex: new RegExp(p.pattern, p.flags)
    }));
    
    this.requireWhereClauseStatements = config.require_where_clause || [];
    this.readOnlyStatements = config.read_only_statements || [];
  }

  validate(query: string, options?: ValidationOptions): SQLValidationResult {
    const normalizedQuery = query.trim().replace(/\s+/g, ' ');
    
    // Check blocked patterns
    for (const pattern of this.blockedPatterns) {
      if (pattern.regex.test(normalizedQuery)) {
        return {
          valid: false,
          reason: pattern.message,
          riskLevel: 'CRITICAL'
        };
      }
    }
    
    // Check injection patterns
    for (const pattern of this.injectionPatterns) {
      if (pattern.regex.test(normalizedQuery)) {
        return {
          valid: false,
          reason: pattern.message,
          riskLevel: 'HIGH'
        };
      }
    }
    
    // Determine query type
    const queryType = this.getQueryType(normalizedQuery);
    
    // Check WHERE clause requirement
    if (this.requireWhereClauseStatements.includes(queryType)) {
      const hasWhere = /WHERE\s+/i.test(normalizedQuery);
      if (!hasWhere) {
        return {
          valid: false,
          reason: `${queryType} statement requires a WHERE clause`,
          queryType,
          hasWhereClause: false,
          riskLevel: 'HIGH'
        };
      }
    }
    
    // Check read-only mode
    if (options?.readOnly && !this.readOnlyStatements.includes(queryType)) {
      return {
        valid: false,
        reason: `Only ${this.readOnlyStatements.join(', ')} statements are allowed in read-only mode`,
        queryType,
        riskLevel: 'MEDIUM'
      };
    }
    
    return {
      valid: true,
      queryType,
      hasWhereClause: /WHERE\s+/i.test(normalizedQuery),
      riskLevel: this.assessRisk(normalizedQuery)
    };
  }

  private getQueryType(query: string): string {
    const match = query.match(/^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|SHOW|DESCRIBE|EXPLAIN)/i);
    return match ? match[1].toUpperCase() : 'UNKNOWN';
  }

  private assessRisk(query: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const queryType = this.getQueryType(query);
    
    switch (queryType) {
      case 'SELECT':
      case 'SHOW':
      case 'DESCRIBE':
      case 'EXPLAIN':
        return 'LOW';
      case 'INSERT':
        return 'MEDIUM';
      case 'UPDATE':
      case 'DELETE':
        return /WHERE\s+/i.test(query) ? 'MEDIUM' : 'HIGH';
      default:
        return 'CRITICAL';
    }
  }
}
```

### Integration with Policy Engine
```typescript
// src/policies/sql-validation-middleware.ts
export class SQLValidationMiddleware implements Middleware {
  constructor(
    private validator: SQLValidator,
    private config: SQLValidationConfig
  ) {}

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    if (context.toolName !== 'database_execute') {
      return { action: 'CONTINUE' };
    }

    const query = context.arguments.query as string;
    if (!query) {
      return {
        action: 'BLOCK',
        reason: 'Missing query argument'
      };
    }

    const result = this.validator.validate(query, {
      readOnly: this.config.read_only
    });

    if (!result.valid) {
      return {
        action: 'BLOCK',
        reason: result.reason,
        metadata: {
          queryType: result.queryType,
          riskLevel: result.riskLevel
        }
      };
    }

    // Log high-risk queries for audit
    if (result.riskLevel === 'HIGH') {
      context.logger.warn('High-risk SQL query detected', {
        query,
        queryType: result.queryType
      });
    }

    return { action: 'CONTINUE' };
  }
}
```

## Error Responses

### Blocked Query
```json
{
  "error": {
    "code": "SQL_VALIDATION_FAILED",
    "message": "Query blocked by SQL validation",
    "details": {
      "reason": "DROP TABLE is not allowed",
      "query_type": "DROP",
      "risk_level": "CRITICAL"
    }
  }
}
```

### Missing WHERE Clause
```json
{
  "error": {
    "code": "SQL_VALIDATION_FAILED",
    "message": "Query blocked by SQL validation",
    "details": {
      "reason": "DELETE statement requires a WHERE clause",
      "query_type": "DELETE",
      "risk_level": "HIGH",
      "has_where_clause": false
    }
  }
}
```

## Testing

### Unit Tests
```typescript
describe('SQLValidator', () => {
  let validator: SQLValidator;

  beforeEach(() => {
    validator = new SQLValidator({
      blocked_patterns: [
        { pattern: 'DROP\\s+TABLE', flags: 'i', message: 'DROP TABLE is not allowed' }
      ],
      injection_patterns: [
        { pattern: 'UNION\\s+(ALL\\s+)?SELECT', flags: 'i', message: 'UNION SELECT is not allowed' }
      ],
      require_where_clause: ['DELETE', 'UPDATE'],
      read_only_statements: ['SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN']
    });
  });

  it('should block DROP TABLE queries', () => {
    const result = validator.validate('DROP TABLE users');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('DROP TABLE is not allowed');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('should block DELETE without WHERE clause', () => {
    const result = validator.validate('DELETE FROM users');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('WHERE clause');
  });

  it('should allow DELETE with WHERE clause', () => {
    const result = validator.validate('DELETE FROM users WHERE id = 1');
    expect(result.valid).toBe(true);
    expect(result.hasWhereClause).toBe(true);
  });

  it('should detect UNION SELECT injection', () => {
    const result = validator.validate("SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords");
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('UNION SELECT is not allowed');
  });

  it('should enforce read-only mode', () => {
    const result = validator.validate('INSERT INTO users VALUES (1, "test")', { readOnly: true });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('read-only mode');
  });

  it('should allow SELECT in read-only mode', () => {
    const result = validator.validate('SELECT * FROM users', { readOnly: true });
    expect(result.valid).toBe(true);
  });
});
```

## Output
- Comprehensive SQL validation
- Injection pattern detection
- Destructive operation blocking
- WHERE clause enforcement
- Read-only mode support
- Risk level assessment

## Related Skills
- `policy-engine` - Integrate SQL validation as a policy
- `audit-logger` - Log blocked SQL queries
- `security-review` - Review SQL validation rules

# Skill: Policy Engine

## Description
Implement and configure policy rules for the tool-use-firewall. The policy engine is the core component that evaluates incoming tool calls against configured rules and determines whether to allow, block, or require approval.

## When to Use
- Implementing new policy rules
- Configuring tool-specific restrictions
- Setting up default behaviors
- Modifying policy evaluation logic

## Capabilities
- Create policy schema with Zod validation
- Implement rule evaluation engine
- Support multiple rule types (allow, block, approval_required)
- Handle rule priority and ordering
- Support tool name pattern matching
- Implement condition evaluation

## Policy Structure

```yaml
# policy.yaml
version: "1.0"

settings:
  default_action: "BLOCK"  # Default deny
  
rules:
  - id: "block_drop_table"
    type: "block"
    tools: ["database_execute"]
    conditions:
      - argument: "query"
        pattern: "DROP\\s+TABLE"
        flags: "i"
    priority: 100
    
  - id: "require_approval_for_delete"
    type: "approval_required"
    tools: ["database_execute"]
    conditions:
      - argument: "query"
        pattern: "DELETE\\s+FROM"
        flags: "i"
    priority: 90
    
  - id: "allow_select"
    type: "allow"
    tools: ["database_execute"]
    conditions:
      - argument: "query"
        pattern: "^SELECT\\s+"
        flags: "i"
    priority: 80
```

## Implementation

### Policy Engine Interface
```typescript
// src/policies/engine.ts
export interface PolicyEngine {
  loadPolicy(config: PolicyConfig): Promise<void>;
  evaluate(context: RequestContext): Promise<EvaluationResult>;
  reload(): Promise<void>;
}

export interface EvaluationResult {
  action: 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED';
  rule?: Rule;
  reason?: string;
}
```

### Rule Evaluation
```typescript
// src/policies/rule-evaluator.ts
export class RuleEvaluator {
  async evaluate(
    rules: Rule[], 
    context: RequestContext
  ): Promise<EvaluationResult> {
    // Sort by priority (highest first)
    const sortedRules = rules.sort((a, b) => b.priority - a.priority);
    
    for (const rule of sortedRules) {
      if (this.matchesTool(rule, context.toolName)) {
        if (await this.matchesConditions(rule.conditions, context)) {
          return {
            action: rule.type.toUpperCase(),
            rule,
            reason: rule.description
          };
        }
      }
    }
    
    return { action: 'ALLOW' }; // Or default action
  }
}
```

## Configuration Options

### Rule Types
- `allow` - Permit the tool call
- `block` - Deny the tool call
- `approval_required` - Require human approval before proceeding

### Condition Types
- `pattern` - Regex pattern matching on argument value
- `equals` - Exact value match
- `contains` - Substring match
- `gt` / `lt` - Numeric comparisons
- `custom` - Custom validation function

### Tool Matching
- Exact match: `"database_execute"`
- Wildcard: `"database_*"`
- Regex: `"/^database_.*/"`

## Testing

### Unit Tests
```typescript
describe('PolicyEngine', () => {
  it('should block DROP TABLE queries', async () => {
    const engine = new PolicyEngine(policyConfig);
    const result = await engine.evaluate({
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' }
    });
    
    expect(result.action).toBe('BLOCK');
    expect(result.rule?.id).toBe('block_drop_table');
  });
});
```

## Output
- Fully functional policy engine
- Configurable policy rules via YAML
- Rule evaluation with proper priority handling
- Comprehensive test coverage

## Related Skills
- `sql-validator` - SQL-specific validation rules
- `approval-workflow` - Approval-required rule handling
- `testing` - Test policy engine implementation

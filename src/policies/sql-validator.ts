import { safeRegExp } from '../utils/safe-regex.js';

export interface SQLValidationResult {
  valid: boolean;
  reason?: string;
  queryType?: string;
  hasWhereClause?: boolean;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface SQLValidationConfig {
  blocked_patterns: Array<{
    pattern: string;
    flags?: string;
    message: string;
  }>;
  injection_patterns: Array<{
    pattern: string;
    flags?: string;
    message: string;
  }>;
  require_where_clause?: string[];
  read_only_statements?: string[];
}

interface CompiledPattern {
  regex: RegExp;
  message: string;
}

/**
 * Comprehensive SQL validation for database tool calls.
 * Blocks destructive operations, detects injection patterns, enforces WHERE clauses.
 */
export class SQLValidator {
  private blockedPatterns: CompiledPattern[] = [];
  private injectionPatterns: CompiledPattern[] = [];
  private requireWhereClauseStatements: string[] = [];
  private readOnlyStatements: string[] = [];

  constructor(config: SQLValidationConfig) {
    this.blockedPatterns = config.blocked_patterns.map((p) => {
      try {
        return {
          regex: safeRegExp(p.pattern, p.flags ?? ''),
          message: p.message,
        };
      } catch {
        // Fallback: create a regex that never matches so the pattern is ignored
        return { regex: /(?!)/, message: p.message };
      }
    });
    this.injectionPatterns = config.injection_patterns.map((p) => {
      try {
        return {
          regex: safeRegExp(p.pattern, p.flags ?? ''),
          message: p.message,
        };
      } catch {
        return { regex: /(?!)/, message: p.message };
      }
    });
    this.requireWhereClauseStatements = config.require_where_clause ?? ['DELETE', 'UPDATE'];
    this.readOnlyStatements = config.read_only_statements ?? [
      'SELECT',
      'SHOW',
      'DESCRIBE',
      'EXPLAIN',
    ];
  }

  validate(query: string, options?: { readOnly?: boolean }): SQLValidationResult {
    const normalizedQuery = query.trim().replace(/\s+/g, ' ');

    // Check blocked patterns
    for (const pattern of this.blockedPatterns) {
      if (pattern.regex.test(normalizedQuery)) {
        return {
          valid: false,
          reason: pattern.message,
          riskLevel: 'CRITICAL',
        };
      }
    }

    // Check injection patterns
    for (const pattern of this.injectionPatterns) {
      if (pattern.regex.test(normalizedQuery)) {
        return {
          valid: false,
          reason: pattern.message,
          riskLevel: 'HIGH',
        };
      }
    }

    // Determine query type
    const queryType = this.getQueryType(normalizedQuery);

    // Check WHERE clause requirement
    if (queryType && this.requireWhereClauseStatements.includes(queryType)) {
      const hasWhere = /WHERE\s+/i.test(normalizedQuery);
      if (!hasWhere) {
        return {
          valid: false,
          reason: `${queryType} statement requires a WHERE clause`,
          queryType,
          hasWhereClause: false,
          riskLevel: 'HIGH',
        };
      }
    }

    // Check read-only mode
    if (options?.readOnly && queryType && !this.readOnlyStatements.includes(queryType)) {
      return {
        valid: false,
        reason: `Only ${this.readOnlyStatements.join(', ')} statements are allowed in read-only mode`,
        queryType,
        riskLevel: 'MEDIUM',
      };
    }

    return {
      valid: true,
      queryType,
      hasWhereClause: /WHERE\s+/i.test(normalizedQuery),
      riskLevel: this.assessRisk(normalizedQuery, queryType),
    };
  }

  private getQueryType(query: string): string | undefined {
    const match = query.match(
      /^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|SHOW|DESCRIBE|EXPLAIN)/i,
    );
    return match ? match[1].toUpperCase() : undefined;
  }

  private assessRisk(query: string, queryType?: string): SQLValidationResult['riskLevel'] {
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

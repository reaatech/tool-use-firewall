import type {
  Middleware,
  MiddlewareResult,
  RequestContext,
} from '@reaatech/tool-use-firewall-core';
import { ValidationError } from '@reaatech/tool-use-firewall-core';

interface ToolSchema {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export class SchemaValidator implements Middleware {
  private toolSchemas = new Map<string, ToolSchema>();
  private readonly strict: boolean;

  constructor(config?: { enabled?: boolean; strict?: boolean }) {
    this.strict = config?.strict ?? false;
  }

  updateSchemas(tools: Array<{ name: string; description?: string; inputSchema: unknown }>): void {
    for (const tool of tools) {
      const schema = tool.inputSchema;
      if (schema && typeof schema === 'object') {
        this.toolSchemas.set(tool.name, {
          name: tool.name,
          description: tool.description,
          inputSchema: schema as Record<string, unknown>,
        });
      }
    }
  }

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    if (!context.toolName || !context.arguments || this.toolSchemas.size === 0) {
      return { action: 'CONTINUE' };
    }

    const schema = this.toolSchemas.get(context.toolName);
    if (!schema) return { action: 'CONTINUE' };

    const errors = this.validateArgs(context.arguments, schema);

    if (errors.length > 0) {
      throw new ValidationError({
        message: `Schema validation failed for ${context.toolName}: ${errors.join('; ')}`,
        requestId: context.requestId,
        details: { toolName: context.toolName, errors },
      });
    }

    return { action: 'CONTINUE', metadata: { schemaValidated: true } };
  }

  private validateArgs(args: Record<string, unknown>, schema: ToolSchema): string[] {
    const errors: string[] = [];
    const inputSchema = schema.inputSchema;
    const props = (inputSchema.properties as Record<string, unknown>) ?? {};
    const required = (inputSchema.required as string[]) ?? [];

    for (const key of required) {
      if (!(key in args)) {
        errors.push(`Missing required argument: ${key}`);
      }
    }

    if (!this.strict) return errors;

    if (inputSchema.additionalProperties === false) {
      for (const key of Object.keys(args)) {
        if (!(key in (props as Record<string, unknown>)) && key !== '_meta') {
          errors.push(`Unexpected argument: ${key}`);
        }
      }
    }

    for (const [key, propSchema] of Object.entries(props)) {
      const value = args[key];
      if (value === undefined) continue;

      const ps = propSchema as Record<string, unknown>;
      const expectedType = ps.type;

      if (expectedType === 'string' && typeof value !== 'string') {
        errors.push(`${key}: expected string, got ${typeof value}`);
      } else if (expectedType === 'number' && typeof value !== 'number') {
        errors.push(`${key}: expected number, got ${typeof value}`);
      } else if (expectedType === 'boolean' && typeof value !== 'boolean') {
        errors.push(`${key}: expected boolean, got ${typeof value}`);
      } else if (expectedType === 'array' && !Array.isArray(value)) {
        errors.push(`${key}: expected array, got ${typeof value}`);
      }
    }

    return errors;
  }
}

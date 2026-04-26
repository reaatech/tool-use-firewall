# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model

tool-use-firewall operates as a Zero Trust proxy between AI agents and MCP servers. Every tool call is inspected, validated, and audited before reaching the upstream server. The security model follows these principles:

- **Zero Trust**: No tool call is trusted by default
- **Defense in Depth**: Multiple independent validation layers (rate limiting, argument validation, SQL validation, read-only checks, policy rules)
- **Fail Secure**: Default action is `block` — unknown tools are denied
- **Audit Everything**: All decisions are logged with redacted sensitive data
- **Bounded Resources**: All stateful components (rate limiters, cost trackers, approval queues) implement capacity limits and TTL eviction to prevent memory exhaustion

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

To report a security vulnerability, please use one of these channels:

1. **GitHub Security Advisories** (preferred): Go to [Security > Advisories](https://github.com/reaatech/tool-use-firewall/security/advisories) and click "Report a vulnerability"
2. **Email**: Contact the maintainers at [GitHub Issues](https://github.com/reaatech/tool-use-firewall/issues) for private disclosure instructions

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact
- Suggested fix (if available)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix release**: Depends on severity; critical issues are prioritized for same-week patches

### Disclosure Policy

We follow coordinated disclosure:
1. Reporter submits vulnerability privately
2. We acknowledge and assess within 48 hours
3. We develop and release a fix
4. We publish an advisory after the fix is released
5. Credit is given to the reporter (unless anonymity is requested)

## Known Security Characteristics

- The firewall operates at the JSON-RPC transport layer and does not inspect encrypted traffic at the TLS level
- Bypass tokens use timing-safe comparison via `crypto.timingSafeEqual` to prevent timing attacks
- Regular expressions from policy configurations are validated against ReDoS patterns before compilation
- Audit logs never write to stdout to avoid corrupting the MCP JSON-RPC stream
- Approval API Bearer tokens use timing-safe comparison
- All error responses use JSON-RPC compliant error codes and do not leak internal state

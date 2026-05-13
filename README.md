# @tailsec/scan-sast

Advanced Static Application Security Testing (SAST) scanner. Deeper analysis than basic code scanning — detects deserialization vulnerabilities, SSRF, XXE, JWT weaknesses, command injection, SQL injection, weak cryptography, and more.

[![npm](https://img.shields.io/npm/v/@tailsec/scan-sast)](https://www.npmjs.com/package/@tailsec/scan-sast)
[![CI](https://github.com/tailsec-com/scan-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/tailsec-com/scan-sast)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Features

- Advanced SAST analysis covering 24+ vulnerability classes
- CWE and OWASP mapping for each finding
- Detects deserialization vulnerabilities (Python pickle, Java ObjectInputStream)
- SSRF, XXE, Command Injection, SQL Injection detection
- JWT algorithm confusion and weak secrets
- Weak cryptography detection (MD5, SHA1, DES, RC4)
- Cookie security and CORS misconfigurations
- GraphQL security checks
- JSON output for CI/CD integration
- No external dependencies

## Installation

```bash
npm install -g @tailsec/scan-sast
```

## Usage

```bash
# Scan source files
npx @tailsec/scan-sast "src/**/*.ts" "lib/**/*.py"

# Output as JSON
npx @tailsec/scan-sast ./src --json
```

### Programmatic

```typescript
import { scanSast, formatSastOutput } from '@tailsec/scan-sast';

const findings = scanSast(codeContent, 'filename.ts');
console.log(formatSastOutput(findings));
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--json` | false | Output as JSON |

## Supported Languages

| Language | Extensions |
|----------|------------|
| TypeScript | `.ts`, `.tsx` |
| JavaScript | `.js`, `.jsx` |
| Python | `.py` |

## Detection Rules

| Rule ID | Severity | CWE | OWASP | Title |
|---------|----------|-----|-------|-------|
| sast-pickle | Critical | CWE-502 | A8 | Python pickle deserialization is unsafe |
| sast-java-serialization | Critical | CWE-502 | A8 | Java ObjectInputStream deserialization |
| sast-yaml-unsafe | High | CWE-502 | A8 | YAML deserialization without safe loading |
| sast-xxe | Critical | CWE-611 | A4 | XML External Entity (XXE) vulnerability |
| sast-ssrf | High | CWE-918 | A10 | Server-Side Request Forgery (SSRF) |
| sast-jwt-none | Critical | CWE-345 | A2 | JWT algorithm set to "none" |
| sast-jwt-weak | High | CWE-347 | A2 | JWT using weak secret |
| sast-ssti | Critical | CWE-1336 | A3 | Server-Side Template Injection (SSTI) |
| sast-cmd-injection | Critical | CWE-78 | A1 | OS Command Injection |
| sast-sqli-tuple | Critical | CWE-89 | A1 | SQL injection via tuple construction |
| sast-crypto-hardcoded | Critical | CWE-321 | A2 | Hardcoded cryptographic key detected |
| sast-cors-wildcard | Critical | CWE-346 | A1 | CORS allows wildcard origin |
| sast-crypto-md5 | High | CWE-327 | A2 | MD5 hash algorithm is broken |
| sast-crypto-sha1 | High | CWE-327 | A2 | SHA1 hash algorithm is weak |
| sast-crypto-des | High | CWE-327 | A2 | DES cipher is insecure |
| sast-crypto-rc4 | High | CWE-327 | A2 | RC4 cipher is insecure |
| sast-redos | Medium | CWE-1333 | A1 | Potential Regular Expression DoS (ReDoS) |
| sast-mass-assign | Medium | CWE-915 | A1 | Potential mass assignment vulnerability |
| sast-graphql-introspection | Low | CWE-200 | A1 | GraphQL introspection enabled |
| sast-graphql-depth-limit | Medium | CWE-770 | A1 | GraphQL missing depth limiting |
| sast-cookie-no-secure | Medium | CWE-614 | A2 | Cookie missing secure flag |
| sast-cookie-no-httponly | Medium | CWE-1004 | A2 | Cookie missing httpOnly flag |

## Exit Codes

- `0` — Scan completed, no issues found
- `1` — Scan completed, issues found
- `2` — Scan failed (file errors, parse errors)

## Contributing

Rules are defined in `src/sast.ts` in the `SAST_RULES` array. Each rule has:

- `id` — Rule identifier (e.g., `sast-ssrf`)
- `severity` — One of: `critical`, `high`, `medium`, `low`
- `cwe` — CWE identifier
- `owasp` — OWASP Top 10 category
- `title` — Human-readable description
- `patterns` — Array of RegExp patterns to match

To add a new rule, append to the `SAST_RULES` array:

```typescript
{
  id: 'sast-my-new-rule',
  severity: 'high',
  cwe: 'CWE-XXX',
  owasp: ['A1'],
  title: 'Description of the issue',
  patterns: [/pattern-to-match/],
},
```

Also add corresponding remediation in the `getRemediation()` function.

## License

MIT
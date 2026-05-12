# @tailsec/scan-sast

Advanced SAST (Static Application Security Testing) scanner - deeper security analysis than the basic `scan-code` package.

## Features

Comprehensive security analysis including:

- **Insecure Deserialization**: Python pickle, Java ObjectInputStream, unsafe YAML
- **SSRF**: Server-Side Request Forgery detection
- **XXE**: XML External Entity vulnerabilities
- **Race Conditions**: Timing attack vulnerabilities
- **ReDoS**: Regular Expression Denial of Service
- **IDOR**: Insecure Direct Object Reference
- **Mass Assignment**: Framework-level vulnerabilities
- **JWT Security**: Algorithm confusion, weak secrets
- **SSTI**: Server-Side Template Injection
- **GraphQL**: Introspection, depth limiting issues
- **API Security**: Missing rate limiting, auth issues
- **Cookie Security**: Missing secure/httpOnly flags
- **CORS**: Wildcard origin misconfiguration
- **Weak Crypto**: MD5, SHA1, DES, RC4, hardcoded keys
- **Command Injection**: OS command execution risks
- **SQL Injection**: Tuple construction vulnerabilities

## Installation

```bash
npm install @tailsec/scan-sast
```

## CLI Usage

```bash
tailsec-scan-sast "src/**/*.ts" "lib/**/*.py"
```

## API Usage

```typescript
import { scanSast, formatSastOutput } from '@tailsec/scan-sast';

const findings = scanSast(codeContent, 'filename.ts');
console.log(formatSastOutput(findings));
```

## License

MIT

export interface SastFinding {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  file: string;
  line: number;
  code: string;
  cwe?: string;
  owasp?: string[];
  remediation: string[];
}

export function isBinaryFile(content: Buffer): boolean {
  if (content.length === 0) return true;
  if (content.length < 4) return false;
  const checkLen = Math.min(content.length, 8192);
  for (let i = 0; i < checkLen; i++) {
    if (content[i] === 0) return true;
  }
  return false;
}

const SAST_RULES = [
  { id: 'sast-pickle', severity: 'critical', cwe: 'CWE-502', owasp: ['A8'], title: 'Python pickle deserialization is unsafe',
    patterns: [/\bpickle\.loads?\(/, /\bpickle\.load\(/] },
  { id: 'sast-java-serialization', severity: 'critical', cwe: 'CWE-502', owasp: ['A8'], title: 'Java ObjectInputStream deserialization',
    patterns: [/ObjectInputStream/, /readObject\(\)/] },
  { id: 'sast-yaml-unsafe', severity: 'high', cwe: 'CWE-502', owasp: ['A8'], title: 'YAML deserialization without safe loading',
    patterns: [/yaml\.load\(/, /yaml\.unsafe_load\(/] },

  { id: 'sast-ssrf', severity: 'high', cwe: 'CWE-918', owasp: ['A10'], title: 'Server-Side Request Forgery (SSRF)',
    patterns: [/\brequests?\.get\([^)]*%(?:s|u|r).*format/, /requests?\.get\(.*\+.*(?:url|uri|link)/i] },

  { id: 'sast-xxe', severity: 'critical', cwe: 'CWE-611', owasp: ['A4'], title: 'XML External Entity (XXE) vulnerability',
    patterns: [/etree\.parse/, /ElementTree\.parse/, /minidom\.parse/, /xml\.parse/] },

  { id: 'sast-jwt-none', severity: 'critical', cwe: 'CWE-345', owasp: ['A2'], title: 'JWT algorithm set to "none"',
    patterns: [/algorithm.*:.*["']none["']/i] },
  { id: 'sast-jwt-weak', severity: 'high', cwe: 'CWE-347', owasp: ['A2'], title: 'JWT using weak secret',
    patterns: [/jwt\.verify\(.*secret.*,/i] },

  { id: 'sast-redos', severity: 'medium', cwe: 'CWE-1333', owasp: ['A1'], title: 'Potential Regular Expression Denial of Service (ReDoS)',
    patterns: [/new RegExp\(.*\+.*\)/, /RegExp\(.*\+.*\)/] },

  { id: 'sast-mass-assign', severity: 'medium', cwe: 'CWE-915', owasp: ['A1'], title: 'Potential mass assignment vulnerability',
    patterns: [/Object\.assign\([^,]+,\s*(?:req|request|params)/, /\.\.\.(?:req|request)\b/] },

  { id: 'sast-ssti', severity: 'critical', cwe: 'CWE-1336', owasp: ['A3'], title: 'Server-Side Template Injection (SSTI)',
    patterns: [/render_template_string/, /Template\(.*\.format/, /jinja2\.Environment\([^)]*(?:autoescape|undefined)/] },

  { id: 'sast-graphql-introspection', severity: 'low', cwe: 'CWE-200', owasp: ['A1'], title: 'GraphQL introspection enabled',
    patterns: [/introspection\s*:\s*true/i] },
  { id: 'sast-graphql-depth-limit', severity: 'medium', cwe: 'CWE-770', owasp: ['A1'], title: 'GraphQL missing depth limiting',
    patterns: [/maxDepth\s*:\s*(?:false|null|undefined)/i] },

  { id: 'sast-crypto-md5', severity: 'high', cwe: 'CWE-327', owasp: ['A2'], title: 'MD5 hash algorithm is broken - use SHA-256+',
    patterns: [/\bmd5\s*\(/i, /hashlib\.md5/i, /CryptoJS\.MD5/i] },
  { id: 'sast-crypto-sha1', severity: 'high', cwe: 'CWE-327', owasp: ['A2'], title: 'SHA1 hash algorithm is weak - use SHA-256+',
    patterns: [/\bsha1\s*\(/i, /hashlib\.sha1/i, /SHA1/i] },
  { id: 'sast-crypto-des', severity: 'high', cwe: 'CWE-327', owasp: ['A2'], title: 'DES cipher is insecure - use AES',
    patterns: [/\bDES\.new\(/i, /CryptoJS\.DES/i] },
  { id: 'sast-crypto-rc4', severity: 'high', cwe: 'CWE-327', owasp: ['A2'], title: 'RC4 cipher is insecure',
    patterns: [/RC4/i, /arc4/i] },
  { id: 'sast-crypto-hardcoded', severity: 'critical', cwe: 'CWE-321', owasp: ['A2'], title: 'Hardcoded cryptographic key detected',
    patterns: [/(?:api|secret|private)[_-]?key\s*=\s*["'][A-Za-z0-9+/]{16,}["']/i] },

  { id: 'sast-cookie-no-secure', severity: 'medium', cwe: 'CWE-614', owasp: ['A2'], title: 'Cookie missing secure flag',
    patterns: [/cookie\(.*secure\s*:\s*false/i] },
  { id: 'sast-cookie-no-httponly', severity: 'medium', cwe: 'CWE-1004', owasp: ['A2'], title: 'Cookie missing httpOnly flag',
    patterns: [/cookie\(.*httponly\s*:\s*false/i] },

  { id: 'sast-cors-wildcard', severity: 'critical', cwe: 'CWE-346', owasp: ['A1'], title: 'CORS allows wildcard origin',
    patterns: [/Access-Control-Allow-Origin\s*:\s*["\*]+["']/i, /origin\s*:\s*["\*]["']/i] },

  { id: 'sast-sqli-tuple', severity: 'critical', cwe: 'CWE-89', owasp: ['A1'], title: 'SQL injection via tuple construction',
    patterns: [/execute\s*\(\s*["'].*%.*\(.*\)/] },

  { id: 'sast-cmd-injection', severity: 'critical', cwe: 'CWE-78', owasp: ['A1'], title: 'OS Command Injection',
    patterns: [/os\.system\(/, /subprocess.*shell\s*=\s*true/i, /exec\s*\(/] },
];

export function scanSast(content: string, file: string): SastFinding[] {
  const findings: SastFinding[] = [];
  const lines = content.split('\n');

  for (const rule of SAST_RULES) {
    for (let i = 0; i < lines.length; i++) {
      for (const pattern of rule.patterns) {
        if (pattern.test(lines[i])) {
          findings.push({
            ruleId: rule.id,
            type: 'sast',
            severity: rule.severity,
            title: rule.title,
            file,
            line: i + 1,
            code: lines[i].trim(),
            cwe: rule.cwe,
            owasp: rule.owasp,
            remediation: getRemediation(rule.id),
          });
          break;
        }
      }
    }
  }

  return findings;
}

function getRemediation(ruleId: string): string[] {
  const remediations: Record<string, string[]> = {
    'sast-pickle': ['Use json.loads() instead of pickle for untrusted data', 'Consider using marshmallow or pydantic for serialization'],
    'sast-java-serialization': ['Avoid Java serialization for untrusted data', 'Use JSON or protobuf for data exchange'],
    'sast-yaml-unsafe': ['Use yaml.safe_load() instead of yaml.load()', 'Never use yaml.unsafe_load() with untrusted data'],
    'sast-ssrf': ['Validate and sanitize all user-supplied URLs', 'Use allowlists for permitted domains'],
    'sast-xxe': ['Disable external entity parsing', 'Use defusedxml library for XML parsing'],
    'sast-jwt-none': ['Always specify a strong algorithm like RS256', 'Verify the algorithm is not "none"'],
    'sast-jwt-weak': ['Use a strong secret key (256+ bits)', 'Consider using RS256 instead of HS256'],
    'sast-redos': ['Avoid constructing regex from user input', 'Test regex with pathological input'],
    'sast-mass-assign': ['Explicitly define allowed fields', 'Use input validation schemas'],
    'sast-ssti': ['Never render user input directly in templates', 'Use autoescape and context-aware escaping'],
    'sast-graphql-introspection': ['Disable introspection in production', 'Use a separate admin endpoint for introspection'],
    'sast-graphql-depth-limit': ['Implement depth limiting for queries', 'Set maxDepth in your GraphQL server config'],
    'sast-crypto-md5': ['Use hashlib.sha256() or hashlib.sha3_256() instead'],
    'sast-crypto-sha1': ['Use hashlib.sha256() or hashlib.sha3_256() instead'],
    'sast-crypto-des': ['Use AES cipher (CryptoJS.AES) instead'],
    'sast-crypto-rc4': ['Use AES cipher - RC4 is broken and deprecated'],
    'sast-crypto-hardcoded': ['Store secrets in environment variables or a secrets manager', 'Never commit secrets to version control'],
    'sast-cookie-no-secure': ['Set secure: true for session cookies'],
    'sast-cookie-no-httponly': ['Set httpOnly: true to prevent XSS cookie theft'],
    'sast-cors-wildcard': ['Use explicit origin allowlist instead of wildcard'],
    'sast-sqli-tuple': ['Use parameterized queries for all database operations'],
    'sast-cmd-injection': ['Avoid shell commands with user input', 'Use subprocess with shell=False and argument lists'],
  };
  return remediations[ruleId] || ['Review and fix the security issue'];
}

export function formatSastOutput(findings: SastFinding[]): string {
  if (findings.length === 0) return 'No SAST findings.';

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.severity as keyof typeof bySeverity]++;

  let output = `\n=== SAST Scan Results: ${findings.length} findings ===\n`;
  output += `Critical: ${bySeverity.critical} | High: ${bySeverity.high} | Medium: ${bySeverity.medium} | Low: ${bySeverity.low}\n`;
  output += '─'.repeat(60) + '\n';

  for (const f of findings) {
    output += `\n[${f.severity.toUpperCase()}] ${f.title}\n`;
    output += `  Rule: ${f.ruleId} | File: ${f.file}:${f.line}\n`;
    output += `  Code: ${f.code}\n`;
    if (f.cwe) output += `  CWE: ${f.cwe}\n`;
    output += `  Fix: ${f.remediation.join(' | ')}\n`;
  }

  return output;
}

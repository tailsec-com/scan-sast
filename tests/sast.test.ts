import { scanSast } from '../src/sast.js';

describe('SAST Scanner', () => {
  describe('Insecure Deserialization', () => {
    test('detects Python pickle deserialization', () => {
      const code = `data = pickle.loads(encoded_data)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-pickle');
    });

    test('detects Java ObjectInputStream', () => {
      const code = `ObjectInputStream ois = new ObjectInputStream(input);`;
      const findings = scanSast(code, 'Test.java');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-java-serialization');
    });

    test('detects unsafe YAML load', () => {
      const code = `data = yaml.load(user_input)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-yaml-unsafe');
    });
  });

  describe('SSRF', () => {
    test('detects SSRF via string concatenation', () => {
      const code = `response = requests.get(url + user_url)`;
      const findings = scanSast(code, 'test.py');
      expect(findings.some(f => f.ruleId === 'sast-ssrf')).toBe(true);
    });
  });

  describe('XXE', () => {
    test('detects XML parsing vulnerabilities', () => {
      const code = `tree = etree.parse(xml_file)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-xxe');
    });
  });

  describe('JWT Security', () => {
    test('detects JWT algorithm set to none', () => {
      const code = `jwt.encode(payload, secret, { algorithm: "none" })`;
      const findings = scanSast(code, 'test.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-jwt-none');
    });

    test('detects weak JWT secret', () => {
      const code = `jwt.verify(token, secret, { algorithms: ['HS256'] })`;
      const findings = scanSast(code, 'test.js');
      expect(findings.some(f => f.ruleId === 'sast-jwt-weak')).toBe(true);
    });
  });

  describe('ReDoS', () => {
    test('detects dynamic regex construction', () => {
      const code = `const regex = new RegExp(userInput + pattern)`;
      const findings = scanSast(code, 'test.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-redos');
    });
  });

  describe('Mass Assignment', () => {
    test('detects mass assignment via Object.assign', () => {
      const code = `Object.assign(user, req.body)`;
      const findings = scanSast(code, 'test.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-mass-assign');
    });
  });

  describe('SSTI', () => {
    test('detects render_template_string', () => {
      const code = `render_template_string(user_input)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-ssti');
    });
  });

  describe('GraphQL', () => {
    test('detects GraphQL introspection enabled', () => {
      const code = `introspection: true`;
      const findings = scanSast(code, 'schema.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-graphql-introspection');
    });

    test('detects missing GraphQL depth limit', () => {
      const code = `maxDepth: false`;
      const findings = scanSast(code, 'schema.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-graphql-depth-limit');
    });
  });

  describe('Weak Cryptography', () => {
    test('detects MD5 usage', () => {
      const code = `const hash = md5(password)`;
      const findings = scanSast(code, 'test.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-crypto-md5');
    });

    test('detects SHA1 usage', () => {
      const code = `hashlib.sha1(data)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-crypto-sha1');
    });

    test('detects DES encryption', () => {
      const code = `DES.new(key, DES.MODE_ECB)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-crypto-des');
    });

    test('detects RC4 usage', () => {
      const code = `RC4.new(key)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-crypto-rc4');
    });

    test('detects hardcoded API key', () => {
      const code = `const api_key = "sk1234567890abcdefghij"`;
      const findings = scanSast(code, 'config.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-crypto-hardcoded');
    });
  });

  describe('Cookie Security', () => {
    test('detects cookie missing secure flag', () => {
      const code = `cookie('session', data, { secure: false })`;
      const findings = scanSast(code, 'auth.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-cookie-no-secure');
    });

    test('detects cookie missing httpOnly flag', () => {
      const code = `cookie('session', data, { httpOnly: false })`;
      const findings = scanSast(code, 'auth.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-cookie-no-httponly');
    });
  });

  describe('CORS', () => {
    test('detects CORS wildcard origin', () => {
      const code = `Access-Control-Allow-Origin: "*"`;
      const findings = scanSast(code, 'config.js');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-cors-wildcard');
    });
  });

  describe('Command Injection', () => {
    test('detects os.system usage', () => {
      const code = `os.system(user_input)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-cmd-injection');
    });

    test('detects subprocess shell=true', () => {
      const code = `subprocess.run(cmd, shell=True)`;
      const findings = scanSast(code, 'test.py');
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('sast-cmd-injection');
    });
  });

  describe('Multiple findings', () => {
    test('detects multiple issues in same file', () => {
      const code = `
const api_key = "sk1234567890abcdefghij"
const hash = md5(password)
jwt.encode(payload, secret, { algorithm: "none" })
      `.trim();
      const findings = scanSast(code, 'config.js');
      expect(findings.length).toBeGreaterThanOrEqual(3);
    });
  });
});

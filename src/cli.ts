#!/usr/bin/env node
import { scanSast, formatSastOutput, SastFinding } from './sast.js';
import { glob } from 'glob';
import { readFileSync } from 'fs';

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.go', '.rb', '.php', '.cs', '.c', '.cpp'];

async function main() {
  const patterns = process.argv.slice(2);
  if (patterns.length === 0) {
    console.log('Usage: tailsec-scan-sast <path|pattern>...');
    process.exit(1);
  }

  const allFindings: SastFinding[] = [];

  for (const pattern of patterns) {
    const files = await glob(pattern, { ignore: ['**/node_modules/**', '**/dist/**', '**/build/**'] });
    for (const file of files) {
      if (!EXTENSIONS.some(ext => file.endsWith(ext))) continue;
      try {
        const content = readFileSync(file, 'utf-8');
        const findings = scanSast(content, file);
        allFindings.push(...findings);
      } catch (e) {
        // skip unreadable files
      }
    }
  }

  console.log(formatSastOutput(allFindings));
}

main().catch(console.error);

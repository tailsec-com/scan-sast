#!/usr/bin/env node
import { scanSast, formatSastOutput, SastFinding, isBinaryFile } from './sast.js';
import { glob } from 'glob';
import { readFileSync, statSync } from 'fs';

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.go', '.rb', '.php', '.cs', '.c', '.cpp'];
const MAX_FILE_SIZE = 10 * 1024 * 1024;

async function main() {
  const patterns = process.argv.slice(2);
  if (patterns.length === 0) {
    console.log('Usage: tailsec-scan-sast <path|pattern>...');
    process.exit(1);
  }

  const allFindings: SastFinding[] = [];

  const scanPromises: Promise<void>[] = [];

  for (const pattern of patterns) {
    const files = await (glob as any)(pattern, { ignore: ['**/node_modules/**', '**/dist/**', '**/build/**'] }) as string[];
    for (const file of files) {
      if (!EXTENSIONS.some(ext => file.endsWith(ext))) continue;
      scanPromises.push((async () => {
        try {
          const stats = statSync(file);
          if (stats.size > MAX_FILE_SIZE) {
            return;
          }
          const content = readFileSync(file);
          if (isBinaryFile(content)) {
            return;
          }
          const text = content.toString('utf-8');
          const findings = scanSast(text, file);
          allFindings.push(...findings);
        } catch (e) {
          // skip unreadable files
        }
      })());
    }
  }

  await Promise.all(scanPromises);

  console.log(formatSastOutput(allFindings));
}

main().catch(console.error);
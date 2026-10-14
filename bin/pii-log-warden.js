#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { mainCli, check, RULES, UsageError, splitList } from '../src/index.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const readStdin = async () => { const c = []; for await (const x of process.stdin) c.push(x); return Buffer.concat(c).toString('utf8'); };
mainCli({
  name: 'pii-log-warden', version: pkg.version, configKey: 'piiLogWarden', rules: RULES,
  tagline: 'find and redact PII in log files',
  usage: 'Usage: pii-log-warden [files or dirs...] [options]     (use - to read stdin)',
  dirFrom: () => '.',
  help: `Scan
      --all-files              Scan every file in directories (default: *.log, *.txt, *.jsonl, *.json, *.csv, *.out, *.err, rotated *.log.1)
      --exclude <globs>        Skip matching paths
      --private-ips            Also report private/loopback IP addresses
      --ignore-email-domains <d>  Email domains to ignore (e.g. your service accounts)
      --max-per-file <n>       Findings per rule per file before summarising (default 50)
Redact
      --redact                 Rewrite files with [REDACTED:type] placeholders (in place unless --redact-dir)
      --redact-dir <dir>       Write redacted copies here instead of in place
      --mask                   Use masked values (j***@example.org) instead of placeholders
`,
  options: { 'all-files': { type: 'boolean' }, exclude: { type: 'string', multiple: true }, 'private-ips': { type: 'boolean' }, 'ignore-email-domains': { type: 'string', multiple: true }, 'max-per-file': { type: 'string' }, redact: { type: 'boolean' }, 'redact-dir': { type: 'string' }, mask: { type: 'boolean' } },
  run: async ({ positionals, values: o, config, configFile }) => {
    let mp; if (o['max-per-file'] != null) { mp = Number(o['max-per-file']); if (!(mp >= 1)) throw new UsageError('--max-per-file must be a positive number'); }
    const common = { allFiles: o['all-files'] || undefined, exclude: splitList(o.exclude).length ? splitList(o.exclude) : undefined, privateIps: o['private-ips'] || undefined, ignoreEmailDomains: splitList(o['ignore-email-domains']).length ? splitList(o['ignore-email-domains']) : undefined, maxPerFile: mp, redact: o.redact || !!o['redact-dir'], redactDir: o['redact-dir'], style: o.mask ? 'mask' : undefined, toolVersion: pkg.version };
    if (positionals[0] === '-' ) { let out = null; const r = check([], { ...common, stdinText: await readStdin(), onRedacted: (t) => { out = t; } }, config, configFile); if (out != null) { process.stderr.write(out); } return r; }
    return check(positionals.length ? positionals : ['.'], common, config, configFile);
  },
});

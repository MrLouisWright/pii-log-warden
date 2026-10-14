import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { check, scanText, redactText, luhn, ibanValid, mask, RULES } from '../src/index.js';

const fx = (n) => new URL(`./fixtures/${n}`, import.meta.url).pathname;
const kinds = (t, o) => scanText(t, o).map((h) => h.rule);
const tmp = (files) => { const d = mkdtempSync(join(tmpdir(), 'pl-')); for (const [p, c] of Object.entries(files)) { mkdirSync(join(d, p, '..'), { recursive: true }); writeFileSync(join(d, p), c); } return d; };

test('good fixture is clean', () => { assert.deepEqual(check([fx('good')]).findings, []); });
test('bad fixture finds every PII type', () => { const r = check([fx('bad')]).findings.map((f) => f.rule); for (const k of Object.keys(RULES).filter((k) => k !== 'pii-file-unreadable')) assert.ok(r.includes(k), k); });
test('checksums: Luhn and IBAN', () => {
  assert.ok(luhn('4111111111111111')); assert.ok(!luhn('4111111111111112'));
  assert.ok(ibanValid('GB82 WEST 1234 5698 7654 32')); assert.ok(ibanValid('DE89370400440532013000')); assert.ok(!ibanValid('GB82WEST12345698765433'));
  assert.deepEqual(kinds('order 4111111111111112 total'), []);
});
test('false positives avoided: private IPs, version numbers, timestamps, example.com, masked secrets', () => {
  assert.deepEqual(kinds('ip 192.168.1.10 v1.2.3.4 at 2026-10-14T00:00:00Z mail test@example.com password=******** token=null'), []);
  assert.deepEqual(kinds('ip 192.168.1.10', { privateIps: true }), ['pii-ip-address']);
  assert.deepEqual(kinds('svc@internal.acme.io', { ignoreEmailDomains: ['internal.acme.io'] }), []);
  assert.deepEqual(kinds('id 1111111111111111 uuid 123e4567-e89b-12d3-a456-426614174000'), []);
});
test('IPv6 and US phone formats', () => {
  assert.deepEqual(kinds('from 2001:0db8:85a3:0000:0000:8a2e:0370:7334'), ['pii-ip-address']);
  assert.deepEqual(kinds('call (415) 555-2671'), ['pii-phone']);
});
test('masking', () => { assert.equal(mask('pii-email', 'jane@acme.io'), 'j***@acme.io'); assert.equal(mask('pii-card-number', '4111 1111 1111 1111'), '411111******1111'); assert.ok(!mask('pii-us-ssn', '123-45-6789').includes('45')); });
test('redaction: placeholders, masks, in place and to a directory', () => {
  assert.equal(redactText('to jane@acme.io ok').text, 'to [REDACTED:email] ok');
  assert.equal(redactText('to jane@acme.io ok', { style: 'mask' }).text, 'to j***@acme.io ok');
  const d = tmp({ 'a.log': 'a jane@acme.io\nb 81.2.69.142\n' }); const out = join(d, 'clean');
  const cwd = process.cwd(); process.chdir(d);
  try { const r = check(['a.log'], { redact: true, redactDir: out }); assert.equal(r.info.redacted, 2); assert.equal(readFileSync(join(out, 'a.log'), 'utf8'), 'a [REDACTED:email]\nb [REDACTED:ip-address]\n'); assert.match(readFileSync(join(d, 'a.log'), 'utf8'), /jane/);
    check(['a.log'], { redact: true }); assert.deepEqual(check(['a.log']).findings, []); } finally { process.chdir(cwd); }
});
test('directory walking: log-like files only unless allFiles; binary skipped; maxPerFile summarises', () => {
  const d = tmp({ 'x.log': 'a@b.io', 'y.bin': Buffer.from([0, 1, 2, 3]), 'z.md': 'c@d.io', 'w.log.1': 'e@f.io', 'many.log': Array.from({ length: 60 }, (_, i) => `u${i}@acme.io`).join('\n') });
  const r = check([d], { maxPerFile: 50 });
  assert.equal(r.findings.filter((f) => f.file.endsWith('many.log')).length, 51);
  assert.ok(r.findings.some((f) => f.file.endsWith('w.log.1'))); assert.ok(!r.findings.some((f) => f.file.endsWith('z.md')));
  assert.ok(check([d], { allFiles: true }).findings.some((f) => f.rule === 'pii-file-unreadable'));
});
test('allowlist with expiry', () => {
  const d = tmp({ 'a.log': 'ops@acme.io' });
  const r = check([join(d, 'a.log')], { now: new Date('2026-10-14') }, { allowlist: [{ rule: 'pii-email', reason: 'ops mailbox, not personal', expires: '2027-01-01' }] });
  assert.equal(r.findings.length, 0); assert.equal(r.suppressed.length, 1);
});
test('CLI: exit codes, stdin, formats', () => {
  const bin = new URL('../bin/pii-log-warden.js', import.meta.url).pathname;
  const run = (args, input) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', input });
  assert.equal(run([fx('good'), '--fail-on', 'info']).status, 0);
  assert.equal(run([fx('bad')]).status, 1);
  assert.equal(run([fx('bad'), '--fail-on', 'none']).status, 0);
  assert.equal(run(['/nonexistent-xyz']).status, 2);
  assert.equal(run(['-', '--format', 'json'], 'card 4111111111111111\n').status, 1);
  assert.equal(JSON.parse(run(['-', '--format', 'json', '--fail-on', 'none'], 'mail jane@acme.io').stdout).findings[0].rule, 'pii-email');
  assert.equal(JSON.parse(run([fx('bad'), '--format', 'sarif', '--fail-on', 'none']).stdout).version, '2.1.0');
  assert.ok(!run([fx('bad'), '--format', 'json', '--fail-on', 'none']).stdout.includes('jane.doe@'), 'values are masked in reports');
});

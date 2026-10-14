// pii-log-warden: find and redact PII in log files. Zero dependencies. Louis Wright, MIT.
import { readFileSync, writeFileSync, statSync, readdirSync, mkdirSync } from 'node:fs';
import { join, relative, dirname, resolve } from 'node:path';
import { buildReport, UsageError } from './core.js';

export * from './core.js';

export const RULES = {
  'pii-card-number': { severity: 'critical', title: 'Payment card number (Luhn-valid PAN)' },
  'pii-us-ssn': { severity: 'high', title: 'US Social Security Number' },
  'pii-uk-nino': { severity: 'high', title: 'UK National Insurance number' },
  'pii-iban': { severity: 'high', title: 'IBAN bank account number (checksum-valid)' },
  'pii-password-field': { severity: 'high', title: 'Password or secret value in a key=value / JSON field' },
  'pii-email': { severity: 'medium', title: 'Email address' },
  'pii-phone': { severity: 'medium', title: 'Phone number (E.164, UK or North American format)' },
  'pii-ip-address': { severity: 'low', title: 'Public IP address (personal data under GDPR)' },
  'pii-dob': { severity: 'low', title: 'Date of birth field' },
  'pii-file-unreadable': { severity: 'info', title: 'File could not be read or is binary' },
};

export function luhn(d) { let s = 0; let alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = d.charCodeAt(i) - 48; if (alt) { n *= 2; if (n > 9) n -= 9; } s += n; alt = !alt; } return s % 10 === 0; }
export function ibanValid(raw) { const s = raw.replace(/\s+/g, '').toUpperCase(); if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false; const r = (s.slice(4) + s.slice(0, 4)).replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55)); let m = 0; for (const ch of r) m = (m * 10 + +ch) % 97; return m === 1; }
const privateIp = (ip) => /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|255\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
const ipv4ok = (ip) => ip.split('.').every((o) => +o <= 255 && !(o.length > 1 && o[0] === '0'));
export function mask(rule, v) {
  if (rule === 'pii-email') { const [u, d] = v.split('@'); return `${u[0]}***@${d}`; }
  if (rule === 'pii-card-number') { const d = v.replace(/\D/g, ''); return `${d.slice(0, 6)}******${d.slice(-4)}`; }
  if (rule === 'pii-ip-address') return v.includes(':') ? v.replace(/:[0-9a-f]*:[0-9a-f]*$/i, ':xxxx:xxxx') : v.replace(/\.\d+$/, '.xxx');
  if (rule === 'pii-password-field') return v.replace(/([=:]\s*"?)[^"&\s,}]+/, '$1********');
  return v.length <= 4 ? '****' : `${v.slice(0, 2)}${'*'.repeat(Math.max(3, v.length - 4))}${v.slice(-2)}`;
}

const DETECTORS = [
  { rule: 'pii-password-field', re: /\b(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b("?\s*[=:]\s*"?)([^"&\s,}]{3,})/gi, value: (m) => m[0], check: (m) => !/^(\*+|x+|redacted|null|undefined|true|false|<[^>]+>|\[redacted\]|\$\{.*)$/i.test(m[3]) },
  { rule: 'pii-email', re: /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b/g, check: (m, o) => !(o.ignoreEmailDomains || []).some((d) => m[0].toLowerCase().endsWith('@' + d.toLowerCase())) && !/@(example\.(com|org|net)|localhost)$/i.test(m[0]) },
  { rule: 'pii-card-number', re: /\b(?:\d[ -]?){12,18}\d\b/g, check: (m) => { const d = m[0].replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && /^(4|5[1-5]|2[2-7]|3[47]|6(011|5)|35|3(0[0-5]|[68]))/.test(d) && luhn(d) && !/^(\d)\1+$/.test(d); } },
  { rule: 'pii-us-ssn', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { rule: 'pii-uk-nino', re: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g },
  { rule: 'pii-iban', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, check: (m) => ibanValid(m[0]) },
  { rule: 'pii-phone', re: /(?<![\w.+-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}[ .-]?\d{3,4}[ .-]?\d{3,4}|\(\d{3}\)\s?\d{3}-\d{4}|\b0\d{3,4}[ ]?\d{3}[ ]?\d{3,4})(?![\w.-])/g, check: (m) => { const d = m[0].replace(/\D/g, ''); return d.length >= 10 && d.length <= 15 && !/^(\d)\1+$/.test(d); } },
  { rule: 'pii-ip-address', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){2,6}:(?:[0-9a-f]{1,4}:?){1,6}\b/gi, check: (m, o) => { const ip = m[0]; if (ip.includes('.')) return ipv4ok(ip) && (o.privateIps || !privateIp(ip)); return o.privateIps || !/^(fe80|fc|fd|::1)/i.test(ip); } },
  { rule: 'pii-dob', re: /\b(dob|date[_ -]?of[_ -]?birth|birth[_ -]?date|birthday)\b"?\s*[=:]\s*"?(\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})/gi },
];

/** Scan text. Returns [{ rule, line, column, value, masked }]. */
export function scanText(text, opts = {}) {
  const out = []; const lines = String(text).split(/\r?\n/);
  const enabled = opts.rules ? new Set(opts.rules) : null;
  lines.forEach((ln, i) => {
    const taken = [];
    for (const d of DETECTORS) {
      if (enabled && !enabled.has(d.rule)) continue;
      d.re.lastIndex = 0; let m;
      while ((m = d.re.exec(ln))) {
        const s = m.index; const e = s + m[0].length;
        if (taken.some(([a, b]) => s < b && e > a)) continue;
        if (d.check && !d.check(m, opts)) continue;
        taken.push([s, e]); out.push({ rule: d.rule, line: i + 1, column: s + 1, value: m[0], masked: mask(d.rule, m[0]) });
      }
    }
  });
  return out;
}
/** Replace detected PII with [REDACTED:<type>] (or masked form with style "mask"). */
export function redactText(text, opts = {}) {
  const lines = String(text).split(/(\r?\n)/);
  let n = 0; let li = 0;
  const res = lines.map((ln) => { if (/^\r?\n$/.test(ln)) return ln; li++; const hits = scanText(ln, opts).sort((a, b) => b.column - a.column); for (const h of hits) { n++; const rep = opts.style === 'mask' ? h.masked : `[REDACTED:${h.rule.replace(/^pii-/, '')}]`; ln = ln.slice(0, h.column - 1) + rep + ln.slice(h.column - 1 + h.value.length); } return ln; });
  void li; return { text: res.join(''), count: n };
}

const LOGLIKE = /\.(log|txt|out|err|jsonl|ndjson|json|csv|tsv)(\.\d+)?$/i;
export function listFiles(paths, { all = false, exclude = [] } = {}) {
  const out = [];
  const ex = exclude.map((g) => new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\0').replace(/\*/g, '[^/]*').replace(/\0/g, '.*') + '$'));
  const walk = (p, root) => { let st; try { st = statSync(p); } catch { throw new UsageError(`No such file or directory: ${p}`); } if (st.isDirectory()) { for (const e of readdirSync(p)) { if (e === 'node_modules' || e === '.git') continue; walk(join(p, e), root); } } else if (p === root || all || LOGLIKE.test(p)) { const rel = relative(process.cwd(), p) || p; if (!ex.some((r) => r.test(rel))) out.push(p); } };
  for (const p of paths) walk(resolve(p), resolve(p));
  return out;
}

export function check(paths, opts = {}, config = {}, configFile) {
  const tool = { name: 'pii-log-warden', version: opts.toolVersion || '1.0.0', rules: RULES, emoji: '🔏', defaultFile: 'app.log' };
  const o = { ...config, ...Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined)) };
  const raw = []; let scanned = 0; let bytes = 0; let redacted = 0;
  const inputs = opts.stdinText != null ? [{ name: opts.stdinName || '<stdin>', text: opts.stdinText }] : listFiles(paths, { all: o.allFiles, exclude: o.exclude || [] }).map((f) => ({ name: relative(process.cwd(), f) || f, path: f }));
  const perRule = new Map();
  for (const inp of inputs) {
    let text = inp.text;
    if (text == null) { try { const buf = readFileSync(inp.path); if (buf.subarray(0, 4096).includes(0)) { raw.push({ rule: 'pii-file-unreadable', severity: 'info', file: inp.name, subject: inp.name, message: `${inp.name} looks binary; skipped`, fix: 'Decompress or convert it to text first.' }); continue; } text = buf.toString('utf8'); } catch (e) { raw.push({ rule: 'pii-file-unreadable', severity: 'info', file: inp.name, subject: inp.name, message: `Cannot read ${inp.name}: ${e.code || e.message}`, fix: 'Check permissions.' }); continue; } }
    scanned++; bytes += text.length;
    const hits = scanText(text, o);
    for (const h of hits) {
      const k = `${inp.name}|${h.rule}`; const c = (perRule.get(k) || 0) + 1; perRule.set(k, c);
      if (c > (o.maxPerFile ?? 50)) continue;
      raw.push({ rule: h.rule, severity: RULES[h.rule].severity, file: inp.name, line: h.line, subject: `${inp.name}:${h.masked}`, message: `${RULES[h.rule].title.replace(/ \(.*\)$/, '')} ${h.masked} (col ${h.column})`, fix: 'Stop logging this value (mask it at the logger), then purge or redact existing logs.' });
    }
    for (const [k, c] of perRule) if (k.startsWith(inp.name + '|') && c > (o.maxPerFile ?? 50)) { const rule = k.split('|')[1]; raw.push({ rule, severity: RULES[rule].severity, file: inp.name, subject: `${inp.name}:more`, message: `…and ${c - (o.maxPerFile ?? 50)} more ${rule} match(es) in ${inp.name}`, fix: 'Use --json for the full list.' }); }
    if (opts.redact && inp.path) { const r = redactText(text, o); if (r.count) { const dest = opts.redactDir ? join(resolve(opts.redactDir), relative(process.cwd(), inp.path)) : inp.path; mkdirSync(dirname(dest), { recursive: true }); writeFileSync(dest, r.text); redacted += r.count; } }
    else if (opts.redact && inp.text != null) { const r = redactText(text, o); opts.onRedacted?.(r.text); redacted += r.count; }
  }
  return buildReport(tool, inputs.length === 1 ? inputs[0].name : `${inputs.length} file(s)`, raw, config, { now: opts.now, configFile, summaryLine: `${scanned} file(s), ${(bytes / 1024).toFixed(1)} KB scanned${opts.redact ? `; ${redacted} value(s) redacted` : ''}`, info: { files: scanned, bytes, redacted } });
}

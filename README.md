# pii-log-warden

> Find and redact personal data in log files: emails, phone numbers, IP addresses, card numbers and national IDs.

Logs are where personal data leaks quietly: a debug line prints the whole request body, an error handler dumps the card number, a JSON logger serialises the user object with its email, date of birth and password. Under GDPR, PCI DSS and most security reviews those logs then become regulated data. `pii-log-warden` scans log files, directories or stdin, reports every match **masked** (it never repeats the raw value in its own output) with file, line, severity and a fix, and can redact the files in place or into a clean copy.

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**, runs offline. By Louis Wright.

## Features

- **Detectors:** email addresses, phone numbers (E.164, UK, North American), public IPv4/IPv6 addresses, payment card numbers (Luhn-checked, issuer prefixes), US SSNs, UK National Insurance numbers, IBANs (mod-97 checked), passwords/secrets/API keys in `key=value` and JSON fields, and dates of birth.
- **Low noise:** private and loopback IPs, `example.com`, masked values (`********`, `[REDACTED]`), version strings, timestamps and UUIDs are ignored; add your own service domains with `--ignore-email-domains`.
- **Inputs:** files, directories (log-like files by default: `*.log`, rotated `*.log.1`, `*.txt`, `*.jsonl`, `*.json`, `*.csv`, `*.out`, `*.err`), or `-` for stdin (e.g. `kubectl logs … | pii-log-warden -`). Binary files are skipped.
- **Redaction:** `--redact` rewrites files with `[REDACTED:email]` placeholders (or `--mask` for `j***@acme.io`), `--redact-dir` writes clean copies instead.
- Findings per rule per file are capped (`--max-per-file`, default 50) and summarised.
- Text/JSON/SARIF/Markdown output, `--fail-on`, exit codes 0/1/2, allowlist with expiry, severity overrides, GitHub Action with job summary.

### Scope

pii-log-warden matches patterns in text; it is not a DLP system and will miss free-text names and addresses. Secrets in source code are better handled by a secret scanner.

## Rules

| Rule | Default severity | What it means |
|---|---|---|
| `pii-card-number` | critical | Payment card number (Luhn-valid PAN) |
| `pii-us-ssn` | high | US Social Security Number |
| `pii-uk-nino` | high | UK National Insurance number |
| `pii-iban` | high | IBAN bank account number (checksum-valid) |
| `pii-password-field` | high | Password or secret value in a key=value / JSON field |
| `pii-email` | medium | Email address |
| `pii-phone` | medium | Phone number (E.164, UK or North American format) |
| `pii-ip-address` | low | Public IP address (personal data under GDPR) |
| `pii-dob` | low | Date of birth field |
| `pii-file-unreadable` | info | File could not be read or is binary |
| `allowlist-expired` | medium | An allowlist entry is past its `expires` date |
| `allowlist-unused` | info | An allowlist entry matched nothing |

## Install and run

```bash
npx pii-log-warden logs/
npx pii-log-warden app.log --fail-on medium
kubectl logs deploy/api | npx pii-log-warden - --format json
npx pii-log-warden logs/ --redact-dir logs-clean --mask
```

### Sample output

```text
pii-log-warden — 2 file(s)
2 file(s), 0.3 KB scanned

CRITICAL test/fixtures/bad/app.log:2 Payment card number 411111******1111 (col 48) [pii-card-number]
         ↳ fix: Stop logging this value (mask it at the logger), then purge or redact existing logs.
HIGH     test/fixtures/bad/app.log:3 Password or secret value in a key=value / JSON field password":"******** (col 61) [pii-password-field]
         ↳ fix: Stop logging this value (mask it at the logger), then purge or redact existing logs.
HIGH     test/fixtures/bad/app.log:3 US Social Security Number 12*******89 (col 24) [pii-us-ssn]
         ↳ fix: Stop logging this value (mask it at the logger), then purge or redact existing logs.
HIGH     test/fixtures/bad/app.log:3 UK National Insurance number AB********* C (col 45) [pii-uk-nino]
```

## Options

```text
pii-log-warden 1.0.0 — find and redact PII in log files

Usage: pii-log-warden [files or dirs...] [options]     (use - to read stdin)

Scan
      --all-files              Scan every file in directories (default: *.log, *.txt, *.jsonl, *.json, *.csv, *.out, *.err, rotated *.log.1)
      --exclude <globs>        Skip matching paths
      --private-ips            Also report private/loopback IP addresses
      --ignore-email-domains <d>  Email domains to ignore (e.g. your service accounts)
      --max-per-file <n>       Findings per rule per file before summarising (default 50)
Redact
      --redact                 Rewrite files with [REDACTED:type] placeholders (in place unless --redact-dir)
      --redact-dir <dir>       Write redacted copies here instead of in place
      --mask                   Use masked values (j***@example.org) instead of placeholders

Common
  -c, --config <file>     JSON config (default: .pii-log-warden.json or "piiLogWarden" in package.json)
  -f, --format <fmt>      text (default) | json | sarif | markdown
      --json <file>       Also write a JSON report
      --sarif <file>      Also write SARIF 2.1.0
      --markdown <file>   Also write Markdown (e.g. for a job summary)
      --fail-on <sev>     critical | high | medium | low | info | none (default: high)
      --list-rules        Print rules and default severities
      --no-fixes          Hide fix suggestions in text output
      --no-color          Disable colours
  -v, --version / -h, --help

Exit codes: 0 = passed, 1 = findings at or above --fail-on, 2 = usage, config or read error.
```

## Configuration and allowlist

Options can live in `.pii-log-warden.json` (or a `"piiLogWarden"` key in `package.json`, or `--config <file>`):

```json
{
  "failOn": "medium",
  "severity": {
    "pii-card-number": "low"
  },
  "allowlist": [
    {
      "rule": "pii-email",
      "subject": "*:o***@acme.io",
      "reason": "Ops shared mailbox, not personal data",
      "expires": "2027-03-31"
    }
  ],
  "ignoreEmailDomains": [
    "noreply.acme.io"
  ],
  "privateIps": false,
  "maxPerFile": 50,
  "exclude": [
    "logs/archive/**"
  ]
}
```

- **`severity`** changes a rule's severity, or turns it `"off"`.
- **`allowlist`** entries suppress matching findings. Each needs a `reason` and matches on any combination of `rule`, `file`, `subject` (globs with `*`) and `match` (a substring of the message). Add `expires` (`YYYY-MM-DD`) so the exception is time-boxed: once it lapses the finding comes back along with an `allowlist-expired` finding (medium). Entries that no longer match anything are reported as `allowlist-unused` (info).

The config file is looked up in the target directory first, then in the current directory, so `.pii-log-warden.json` can live at your repository root. Other keys: `ignoreEmailDomains`, `privateIps`, `allFiles`, `exclude` and `maxPerFile`.

## Output and exit codes

- `--format text` (default), `json`, `sarif` (SARIF 2.1.0 for GitHub code scanning) or `markdown` (for job summaries and PR comments). `--json`, `--sarif` and `--markdown` write extra report files in the same run.
- `--fail-on <severity>` sets the threshold (`critical`, `high`, `medium`, `low`, `info`, `none`; default `high`).
- Exit codes: **0** passed, **1** findings at or above `--fail-on`, **2** usage, config or read error.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload
jobs:
  pii-log-warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with: { persist-credentials: false }
      - uses: MrLouisWright/pii-log-warden@v1
        with:
          path: logs
          fail-on: high
          sarif: pii-log-warden.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: pii-log-warden.sarif }
```

| Input | Description | Default |
|---|---|---|
| `path` | Log file or directory to scan | `.` |
| `fail-on` | Failure threshold | `high` |
| `config` | Config file path | |
| `sarif` / `json` | Write SARIF / JSON report to this path | |
| `job-summary` | Add the Markdown report to the job summary | `true` |
| `args` | Extra CLI arguments | |

The action runs the bundled CLI with Node 20; it has no dependencies to install. Pin it to a commit SHA if your policy requires it.

## Library

```js
import { scanText, redactText, check } from "pii-log-warden";
scanText("login jane@acme.io from 81.2.69.142"); // [{ rule, line, column, value, masked }]
redactText(line).text; // "login [REDACTED:email] from [REDACTED:ip-address]"
const report = check(["logs"]);
```

Types are included.

## Requirements

Node.js 18 or newer. Zero runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## Licence

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))

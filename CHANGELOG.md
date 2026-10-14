# Changelog

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- Detectors: email, phone, public IPv4/IPv6, Luhn-valid card numbers, US SSN, UK NINO, IBAN (mod-97), password/secret fields, date of birth.
- Files, directories (log-like files) and stdin; binary files skipped; per-file caps.
- Masked reporting; redaction in place or into a directory, placeholder or mask style.
- Text/JSON/SARIF/Markdown output, `--fail-on`, exit codes 0/1/2, allowlist with expiry, severity overrides.
- Composite GitHub Action with job summary.

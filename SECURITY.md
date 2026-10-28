# Security policy

## Reporting a vulnerability

Please report security issues privately by emailing Revefi support at
[support@revefi.com](mailto:support@revefi.com) rather than opening a public issue. Include the
plugin version (shown by `/plugin`), what you ran, and what you observed. We aim to acknowledge
reports within three business days.

## What this tool sends

The plugin uploads Claude Code session transcripts only after you confirm, and only after redacting
them on your machine. You can inspect exactly what will be sent in the preview folder it writes
before you confirm. A redaction miss is a security issue: please report it as above.

A report with link sharing on can be opened by anyone with the link. Ask Claude to turn link
sharing off, or run `revefi-agent-analyzer share <run> --link off`.

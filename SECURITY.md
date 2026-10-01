# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub private vulnerability reporting](https://github.com/revefi/agent-analyzer/security/advisories/new)
rather than a public issue. Include the version (`revefi-agent-analyzer --version`), what you
ran, and what you observed. We aim to acknowledge reports within three business days.

## What this tool sends

The CLI uploads Claude Code session transcripts only after you confirm, and only after redacting
them on your machine. You can inspect exactly what will be sent in the preview folder it writes
before you confirm. A redaction miss is a security issue: please report it as above.

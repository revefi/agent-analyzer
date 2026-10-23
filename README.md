# Revefi Agent Analyzer

Find the work your coding agent keeps repeating, what it costs, and how to stop paying for it.

`revefi-agent-analyzer` reads your recent Claude Code sessions, redacts them on your machine, and
(only after you say yes) sends them to Revefi for analysis. You get a report link with the
repeated tasks ranked by spend, and concrete fixes for each: a skill, a script, a hook, or a
`CLAUDE.md` rule. Inside Claude Code, the plugin can make those fixes in your repository, asking
you before each one.

## Install

### Claude Code plugin

```text
/plugin marketplace add revefi/agent-analyzer
/plugin install revefi@revefi
```

Then, in any repository, run `/revefi:analyze`. It asks which sessions to scan: this directory,
this project, a project you name, or all projects. You can also say it up front, for example
`/revefi:analyze last 3 days`, `/revefi:analyze all projects` or a project's name. The first
time, it asks you to sign in with Google or an emailed code.

The plugin runs the CLI with your installed Node.js, version 22.12 or newer. Plugins that ship
executables are not installed by claude.ai or Cowork; use Claude Code in a terminal or an IDE.

### Command line

With Node.js 22.12 or newer:

```bash
npm install -g revefi-agent-analyzer
```

Or a standalone binary for macOS or Linux, with no Node needed:

```bash
curl -fsSL https://github.com/revefi/agent-analyzer/releases/latest/download/install.sh | sh
```

The installer checks the binary against the release's `SHA256SUMS`, verifies its GitHub build
attestation when the `gh` CLI is installed (set `REVEFI_VERIFY=1` to require that), and installs
it to `~/.local/bin`. Windows binaries are on the
[releases page](https://github.com/revefi/agent-analyzer/releases).

The binaries are not yet signed by Revefi. Installed with the command above they run normally;
downloaded with a browser, macOS Gatekeeper and Windows SmartScreen will warn before the first
run. To check a download yourself:
`gh attestation verify <file> --repo revefi/agent-analyzer`.

Then, from a repository you work on with Claude Code:

```bash
revefi-agent-analyzer analyze
```

## What leaves your machine

Nothing is sent until you confirm. First, the CLI writes a preview: the exact files it would
upload, already redacted, in `.revefi/upload-preview/<timestamp>/` inside your repository, with a
`REDACTION_REPORT.md` that lists every session and everything that was removed. The `.revefi/`
folder ignores itself in git.

**What is sent:** the transcripts of the Claude Code sessions that started in the window you chose
(7 days by default), from the folders you chose: this repository by default, one folder with
`--project`, or every project with `--all-projects`. That includes your prompts, Claude's replies,
the commands and other tools Claude ran, and the code it wrote. The output of those tools is not
sent. When a tool call failed, only its error message goes: a few lines picked from the output (at
most 6 lines and 500 characters), redacted like the rest. In Claude Code, the plugin asks Claude
Haiku, in your own session, which lines state the error; elsewhere a fixed rule picks them. Subagent
transcripts of those sessions are included. A small summary goes with them: the dates, the session
count, the sizes, and the CLI's name and version.

**What is removed first:**

- secrets in known formats: API keys and tokens (Anthropic, OpenAI, GitHub, GitLab, AWS, Google,
  Slack, Stripe, npm, PyPI, Hugging Face, SendGrid, Databricks, Twilio, Azure), private keys,
  JWTs, authorization and cookie headers, passwords in URLs and on command lines, and values
  under names like `password`, `secret`, `token` or `api_key`;
- personal data in known formats: email addresses, phone numbers written as phone numbers
  (`+44 20 7946 0958`, `(415) 555-0132`) and Indian mobile numbers, payment card numbers
  (including RuPay), IBANs, UPI IDs, US Social Security numbers, Aadhaar and PAN numbers, UK
  National Insurance and Canadian SIN numbers, and IP addresses outside private ranges. Card,
  bank and ID numbers must also pass their checksum;
- every value in `.env` files Claude read or wrote;
- images and long base64 data;
- every tool's output except the error message of a failed call, both in the transcript and in
  the structured copy Claude Code keeps next to it (`toolUseResult`), including file contents
  Claude read and copies of files from before each edit;
- your home folder path, which becomes `~` (also in project folder names).

**What is never sent:** tool output Claude Code saves outside the transcripts (`tool-results/`),
sessions outside the window or the chosen scope, and anything else on your machine.

Redaction recognises known formats; it cannot catch every kind of sensitive text. People's
names and street addresses are not detected, because the detectors for them also rewrite
ordinary code. Read the preview if a session touched something you would not share, and leave
sessions out with `--exclude-session <id>`.

To remove everything you have uploaded with your account, at any time:

```bash
revefi-agent-analyzer delete-my-data
```

## Commands

| Command | What it does |
| --- | --- |
| `analyze` | Prepare a preview, ask once, upload, wait, and print the report link and top tasks |
| `projects` | List the folders with sessions in the window, to pick one for `--project` |
| `prepare` | Write the redacted preview only; uploads nothing |
| `upload <preview>` | Upload a prepared preview, then wait for the report |
| `status <run>` | Show a run's progress; `--wait` follows it to the end |
| `recommendations <run>` | Print the recommendations of a finished run |
| `feedback <run> <rec> up\|down` | Rate a recommendation |
| `share <run>` | Show who can open a report; `--add EMAIL`, `--remove EMAIL` and `--link on\|off` change it |
| `delete-my-data` | Delete every run, upload and report made with your account |
| `login` / `logout` / `whoami` | Sign in (Google or an emailed code), sign out, or show who you're signed in as |

Common options: `--days N` (1 to 7), `--all-projects`, `--project DIR` (sessions started in
`DIR` or below; `projects` lists the folders that have any), `--exclude-session ID`, `--yes`
(don't ask), `--json`. Run `revefi-agent-analyzer --help` for all of them.

### Signing in

You sign in with Google or an emailed code; the first sign-in creates your
account, and both ways open the same account for the same email. `revefi-agent-analyzer login`
shows a link and a short code, and in a terminal opens your browser (`--no-browser` skips that):
check that the page shows the same code, then continue with Google or an emailed code.
`analyze` in a terminal does this for you the first time. In a script, run
`login --start --json` to get the link and code, then `login --wait`.

The CLI keeps a refresh token and the current access token in
`~/.config/revefi/agent-analyzer/` (`%APPDATA%\revefi\agent-analyzer\` on Windows), never the
transcripts. On macOS and Linux the files are readable only by you; on Windows they rely on your
user folder's permissions. `logout` removes them and, when the server can be reached, revokes
the sign-in. Each server you point the CLI at with `--api` gets its own sign-in.

### Sharing a report

A report is private: only you can open it. `share <run> --add someone@company.com` lets that
person open it once they sign in with that email, and `share <run> --link on` lets anyone
signed in who has the link open it. The report page has the same controls.

### Scripting

With `--json`, commands print one JSON object on stdout; progress and messages go to stderr, and
failures print `{"error": {"kind": ..., "message": ...}}`. Exit codes: `0` done, `1` failed or
refused, `2` bad usage, `3` the analysis is still running (check again with `status --wait`).

## Development

```bash
pnpm install
pnpm test
pnpm build    # writes dist/ and the plugin's bundled copy in integrations/claude-code/lib/
```

The plugin is installed straight from this repository, so its bundle is committed; CI fails if
it differs from a fresh build. To release, bump `version` in both `package.json` and
`integrations/claude-code/.claude-plugin/plugin.json`, merge, and push a `vX.Y.Z` tag on `main`.
The release workflow tests every binary on its own platform, attests the build, and publishes
to npm through trusted publishing; the `release` environment must approve it. Claude Code
updates installed plugins when that version changes.

## Security and license

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Licensed under the
[Apache License 2.0](LICENSE).

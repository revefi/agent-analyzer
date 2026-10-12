import { parseArgs } from "node:util";
import { ApiError, ISSUES_URL } from "./api.js";
import { SignInError } from "./auth.js";
import { askYesNo, COMMANDS, type Env, type Io, UsageError, UserError } from "./commands.js";
import { PreviewError } from "./preview.js";

declare const __VERSION__: string;
export const VERSION = typeof __VERSION__ === "string" ? __VERSION__ : "0.0.0-dev";

export type { Io };

export const USAGE = `Usage: revefi-agent-analyzer <command> [options]

Find repeated work and wasted spend in your Claude Code sessions.

Commands:
${Object.entries(COMMANDS)
  .map(([name, c]) => `  ${name.padEnd(17)}${c.summary}`)
  .join("\n")}

Options for analyze and prepare:
  --days N               Days of history to analyze, 1-7 (default 7)
  --all-projects         Every project on this machine, not just this repository
  --exclude-session ID   Leave a session out (repeatable; a prefix of the id is enough)

Options for login:
  --start                Print the sign-in link and code, then exit (--json for a script)
  --wait                 Wait for a started sign-in to be approved
  --no-browser           Don't open the browser; just print the link

Other options:
  -y, --yes              Don't ask before uploading (analyze, upload) or deleting (delete-my-data)
  --json                 One JSON object on stdout (login, whoami, prepare, upload, status,
                         recommendations);
                         progress and messages go to stderr; errors print {"error": ...}
  --wait                 status: follow the run until it finishes
  --no-wait              upload: return as soon as the analysis has started
  --timeout SECONDS      How long to wait for the report (analyze 1800, upload and status 480),
                         or for login to be approved (default: until the code expires)
  --api URL              Analyzer server (default REVEFI_ANALYZER_API, else analyzer.revefi.com)
  -h, --help             Show this help
  -v, --version          Show the version

A preview is a folder under .revefi/upload-preview/ holding exactly the redacted files that will
be sent. It is removed once uploaded.

Exit codes: 0 done, 1 failed or refused, 2 bad usage, 3 the analysis is still running.
Environment: CLAUDE_CONFIG_DIR (where Claude Code keeps sessions), REVEFI_ANALYZER_API,
REVEFI_DEBUG=1 (show stack traces).`;

const consoleIo: Io = { out: console.log, err: console.error };

export function defaultEnv(io: Io = consoleIo): Env {
  return {
    io,
    version: VERSION,
    cwd: process.cwd(),
    env: process.env,
    isTTY: Boolean(process.stdin.isTTY && process.stderr.isTTY),
    ask: askYesNo,
  };
}

type ErrorKind = "usage" | "sign_in" | "refused" | "server" | "unexpected";

function classify(err: unknown, debug: boolean): { kind: ErrorKind; message: string; status?: number } {
  if (err instanceof UsageError) return { kind: "usage", message: err.message };
  if (err instanceof SignInError) return { kind: "sign_in", message: err.message };
  if (err instanceof ApiError) return { kind: "server", message: err.message, status: err.status };
  if (err instanceof UserError || err instanceof PreviewError) return { kind: "refused", message: err.message };
  const e = err as Error;
  return {
    kind: "unexpected",
    message: `Something unexpected went wrong: ${debug ? e.stack : e.message}\nPlease report it at ${ISSUES_URL}${debug ? "" : " (set REVEFI_DEBUG=1 for details)"}.`,
  };
}

export async function main(argv: string[], e: Env = defaultEnv()): Promise<number> {
  const [command, ...rest] = argv;
  if (command === undefined || command.startsWith("-")) {
    let values;
    try {
      ({ values } = parseArgs({
        args: argv,
        options: { help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" } },
      }));
    } catch (err) {
      e.io.err(`${(err as Error).message}\n\n${USAGE}`);
      return 2;
    }
    e.io.out(values.version ? VERSION : USAGE);
    return 0;
  }
  const cmd = COMMANDS[command];
  if (!cmd) {
    e.io.err(`Unknown command: ${command}\n\n${USAGE}`);
    return 2;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    e.io.out(USAGE);
    return 0;
  }
  try {
    return await cmd.run(rest, e);
  } catch (err) {
    const { kind, message, status } = classify(err, Boolean(e.env.REVEFI_DEBUG));
    if (rest.includes("--json")) e.io.out(JSON.stringify({ error: { kind, message, ...(status ? { status } : {}) } }));
    e.io.err(kind === "usage" ? `${message}\n\nRun \`revefi-agent-analyzer --help\` for usage.` : message);
    return kind === "usage" ? 2 : 1;
  }
}

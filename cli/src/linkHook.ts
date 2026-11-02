/**
 * Claude Code shows a hook's `systemMessage` to the user whatever the model writes, so the plugin
 * prints the sign-in and report links from here rather than trusting the model to repeat them.
 * The message carries Revefi's name, so it only ever shows a link this CLI produced for its server.
 */

export interface HookInput {
  tool_input?: { command?: unknown };
  tool_response?: { stdout?: unknown };
  error?: unknown;
}

export type HookCommand = { kind: "start" | "upload" | "status"; api?: string };

// One plain invocation: anything that could run a second program, or feed it, is refused.
const SHELL_SYNTAX = /[;&|`$<>(){}\\\n\r]/;
// Printable text only, so nothing can style or rewrite the terminal.
const PLAIN = /^[^\s\u0000-\u001f\u007f-\u009f]+$/;
const CODE = /^[A-Z0-9-]{4,32}$/;
const FINAL_PHASES = new Set(["done", "failed", "deferred"]);

/** Which of the plugin's own commands this is, or null for anything else. */
export function hookCommand(command: unknown): HookCommand | null {
  if (typeof command !== "string" || SHELL_SYNTAX.test(command)) return null;
  const words = command.trim().split(/\s+/);
  if (words[0] !== "revefi-agent-analyzer") return null;
  const sub = words[1];
  const kind = sub === "login" && words.includes("--start") ? "start" : sub === "upload" ? "upload" : sub === "status" ? "status" : null;
  if (!kind) return null;
  const at = words.findIndex((w) => w === "--api" || w.startsWith("--api="));
  const flag = at < 0 ? undefined : words[at];
  const raw = flag === undefined ? undefined : flag === "--api" ? words[at + 1] : flag.slice("--api=".length);
  return { kind, api: raw?.replace(/^['"]|['"]$/g, "") };
}

/**
 * The CLI's own JSON line: all of stdout, or for a failed call the first JSON line after
 * `Exit code N`. Claude Code interleaves a failed call's stdout and stderr in time order, so
 * progress lines can come first; with one bare invocation, every line is still this CLI's.
 */
function cliJson(input: HookInput): Record<string, unknown> | null {
  const stdout = typeof input.tool_response?.stdout === "string" ? input.tool_response.stdout : undefined;
  const failed =
    typeof input.error === "string" && /^Exit code \d+\n/.test(input.error)
      ? input.error.split("\n").slice(1).find((line) => line.startsWith("{"))
      : undefined;
  const text = (stdout ?? failed ?? "").trim();
  if (!text.startsWith("{") || text.includes("\n")) return null;
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function sameServer(link: string, apiBase: string, canonicalHost: (host: string) => string): boolean {
  try {
    const [url, api] = [new URL(link), new URL(apiBase)];
    return url.protocol === api.protocol && canonicalHost(url.host) === canonicalHost(api.host) && !url.username && !url.password;
  } catch {
    return false;
  }
}

export interface LinkContext {
  apiBase: string;
  /** The sign-in this CLI started and validated; only consulted after `login --start`. */
  pending: { verification_uri_complete: string; user_code: string } | null;
  canonicalHost: (host: string) => string;
}

/** The message to show for one finished call, or null when it printed no link worth repeating. */
export function linkMessage(cmd: HookCommand, input: HookInput, ctx: LinkContext): string | null {
  if (cmd.kind === "start") {
    const p = ctx.pending;
    if (!p || !PLAIN.test(p.verification_uri_complete) || !CODE.test(p.user_code)) return null;
    return `Sign in to Revefi: open this link and check it shows the code ${p.user_code}.\n${p.verification_uri_complete}`;
  }
  const body = cliJson(input);
  const url = typeof body?.report_url === "string" ? body.report_url : undefined;
  if (!url || !PLAIN.test(url) || !sameServer(url, ctx.apiBase, ctx.canonicalHost)) return null;
  if (cmd.kind === "upload") return `Your Revefi report (it fills in as the analysis runs):\n${url}`;
  if (!FINAL_PHASES.has(String(body?.phase))) return null;
  return body?.phase === "done" ? `Your Revefi report is ready:\n${url}` : `Your Revefi report:\n${url}`;
}

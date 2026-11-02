/**
 * Claude Code shows a hook's `systemMessage` to the user whatever the model writes, so the plugin
 * prints the sign-in and report links from here rather than trusting the model to repeat them.
 */

interface HookInput {
  tool_input?: { command?: unknown };
  tool_response?: { stdout?: unknown };
  error?: unknown;
}

// Only text the CLI itself produced: a URL with no spaces or control characters, and a code made of
// the characters Auth0 uses, so nothing in a crafted output can style or rewrite the terminal.
const SAFE_URL = /^https?:\/\/[^\s\u0000-\u001f\u007f-\u009f]+$/;
const SAFE_CODE = /^[A-Z0-9-]{4,32}$/;
const FINAL_PHASES = new Set(["done", "failed", "deferred"]);

/** The first line of output that parses as a JSON object. A failed call's text is `Exit code N`, stdout, then stderr. */
function jsonFrom(text: string): Record<string, unknown> | null {
  for (const line of text.split("\n")) {
    if (!line.startsWith("{")) continue;
    try {
      const value: unknown = JSON.parse(line);
      if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
    } catch {
      // Not the JSON line; keep looking.
    }
  }
  return null;
}

const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/** The message to show for one finished Bash call, or null when it printed no link worth repeating. */
export function linkMessage(input: HookInput): string | null {
  const command = str(input.tool_input?.command) ?? "";
  const output = str(input.tool_response?.stdout) ?? str(input.error) ?? "";
  const body = jsonFrom(output);
  if (!body) return null;
  if (/\blogin\b/.test(command) && /--start\b/.test(command)) {
    const url = str(body.verification_uri_complete);
    const code = str(body.user_code);
    if (!url || !SAFE_URL.test(url) || !code || !SAFE_CODE.test(code)) return null;
    return `Sign in to Revefi: open this link and check it shows the code ${code}.\n${url}`;
  }
  const url = str(body.report_url);
  if (!url || !SAFE_URL.test(url)) return null;
  if (/\bupload\b/.test(command)) return `Your Revefi report (it fills in as the analysis runs):\n${url}`;
  if (/\bstatus\b/.test(command) && FINAL_PHASES.has(str(body.phase) ?? "")) {
    return body.phase === "done" ? `Your Revefi report is ready:\n${url}` : `Your Revefi report:\n${url}`;
  }
  return null;
}

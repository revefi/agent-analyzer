/**
 * Client-side redaction of Claude Code transcripts, applied before anything is written to the
 * upload preview. Several patterns are adapted from gitleaks (MIT, github.com/gitleaks/gitleaks).
 *
 * Every pattern must stay linear on multi-megabyte tool output: quantifiers are bounded and no
 * unbounded run precedes a literal the engine would have to backtrack to.
 */

import { encodeProjectDir } from "./collect.js";
import { scrubPersonalData } from "./pii.js";

export type Counts = Record<string, number>;

interface Rule {
  id: string;
  re: RegExp;
  /** Receives the match and its groups; returns the replacement. */
  to: (g: string[]) => string;
}

const fixed = (s: string) => () => s;
const keep1 = (s: string) => (g: string[]) => `${g[1] ?? ""}${s}`;

const RULES: Rule[] = [
  {
    // A key cut off by `head` or a Read limit has no END line; redact to the end of the text.
    id: "private-key",
    re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|[\s\S]*$)/g,
    to: fixed("<PRIVATE_KEY>"),
  },
  {
    id: "anthropic-key",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,300}/g,
    to: fixed("<ANTHROPIC_KEY>"),
  },
  {
    id: "openai-key",
    re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,300}/g,
    to: fixed("<OPENAI_KEY>"),
  },
  {
    id: "github-token",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{22,255})/g,
    to: fixed("<GITHUB_TOKEN>"),
  },
  {
    id: "gitlab-token",
    re: /\bglpat-[\w-]{20,64}/g,
    to: fixed("<GITLAB_TOKEN>"),
  },
  {
    id: "aws-access-key",
    re: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
    to: fixed("<AWS_ACCESS_KEY>"),
  },
  {
    id: "aws-secret-key",
    re: /(\baws[\w.-]{0,20}(?:secret|sk)[\w.-]{0,20}["'\s:=]{1,5})[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/gi,
    to: keep1("<AWS_SECRET>"),
  },
  {
    id: "slack-token",
    re: /\bxox[abeoprs]-[A-Za-z0-9-]{10,255}/g,
    to: fixed("<SLACK_TOKEN>"),
  },
  {
    id: "slack-webhook",
    re: /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[\w/+-]{20,200}/g,
    to: fixed("<SLACK_WEBHOOK>"),
  },
  {
    id: "stripe-key",
    re: /\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b/g,
    to: fixed("<STRIPE_KEY>"),
  },
  {
    id: "google-api-key",
    re: /\bAIza[A-Za-z0-9_-]{35}/g,
    to: fixed("<GOOGLE_API_KEY>"),
  },
  {
    id: "google-oauth",
    re: /\b(?:ya29\.[\w-]{20,2048}|GOCSPX-[\w-]{28})/g,
    to: fixed("<GOOGLE_OAUTH>"),
  },
  { id: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, to: fixed("<NPM_TOKEN>") },
  {
    id: "pypi-token",
    re: /\bpypi-AgEIcHlwaS5vcmc[\w-]{50,300}/g,
    to: fixed("<PYPI_TOKEN>"),
  },
  {
    id: "huggingface-token",
    re: /\bhf_[A-Za-z]{34,64}\b/g,
    to: fixed("<HF_TOKEN>"),
  },
  {
    id: "sendgrid-key",
    re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/g,
    to: fixed("<SENDGRID_KEY>"),
  },
  {
    id: "databricks-token",
    re: /\bdapi[a-f0-9]{32}(?:-\d)?\b/g,
    to: fixed("<DATABRICKS_TOKEN>"),
  },
  { id: "twilio-key", re: /\bSK[0-9a-fA-F]{32}\b/g, to: fixed("<TWILIO_KEY>") },
  {
    id: "azure-client-secret",
    re: /\b[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}\b/g,
    to: fixed("<AZURE_SECRET>"),
  },
  {
    id: "azure-sas",
    re: /([?&]sig=)[^&\s"']{1,512}/g,
    to: keep1("<SIGNATURE>"),
  },
  {
    id: "jwt",
    re: /\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}/g,
    to: fixed("<JWT>"),
  },
  {
    id: "auth-header",
    re: /\b((?:Proxy-)?Authorization\s{0,5}:\s{0,5}(?:[A-Za-z-]{1,20}\s{1,5})?)[^\s"'<]{8,4096}/gi,
    to: keep1("<TOKEN>"),
  },
  {
    id: "cookie-header",
    re: /\b((?:Set-)?Cookie\s{0,5}:\s{0,5})[^\r\n"'<]{1,4096}/gi,
    to: keep1("<COOKIE>"),
  },
  {
    id: "bearer-token",
    re: /\b([Bb]earer\s{1,5})[A-Za-z0-9._~+/-]{20,4096}=*/g,
    to: keep1("<TOKEN>"),
  },
  {
    id: "url-credentials",
    re: /(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s/:@'"]{0,256}:[^\s'"]{0,512}@/gi,
    to: keep1("<CREDENTIALS>@"),
  },
  {
    id: "cli-password",
    re: /(\s--?(?:password|passwd|pass|token|api-key|secret)(?:\s{1,5}|=))(?!-|<)[^\s"']{1,512}/gi,
    to: keep1("<REDACTED>"),
  },
  {
    id: "cli-password",
    re: /(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]{0,200}?\s-p)(?![\s<])[^\s"']{1,512}/g,
    to: keep1("<REDACTED>"),
  },
  {
    id: "cli-password",
    re: /(\s(?:-u|--user)\s{1,5}[^\s:'"]{1,128}:)(?!<)[^\s'"]{1,512}/g,
    to: keep1("<REDACTED>"),
  },
  {
    // `name = value` where the name says it holds a secret. Code that merely mentions such a
    // name (`token: string`, `getToken(req)`, `config.token;`, `${TOKEN}`, `process.env.X`) is
    // left alone; a bare word before `;` could be the secret itself, so it is redacted.
    id: "secret-assignment",
    re: /(?<![\w.-])((?:\\?")?[\w.-]{0,40}?(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|account[_-]?key|credentials?|token)(?:\\?")?)(\s{0,5}[=:]\s{0,5})(?!["']?<|[A-Za-z_$][\w$]{0,100}\s{0,5}\(|[A-Za-z_$][\w$]{0,100}(?:\.[A-Za-z_$][\w$]{0,100}){1,10}\s{0,5}[(;]|(?:string|number|boolean|undefined|null|true|false)\b|\$\{|process\.env|os\.environ)(?:\\"[^"\\\n]{1,512}\\"|"[^"\n]{1,512}"|'[^'\n]{1,512}'|[^\s"',;}<)\\]{4,512})/gi,
    to: (g) => `${g[1] ?? ""}${g[2] ?? ""}<REDACTED>`,
  },
];

/** A `.env`-style line, also as printed by the Read tool with a `  12→` line-number prefix. */
const ENV_LINE =
  /^(\s{0,20}(?:\d{1,9}[→\t]\s{0,5})?(?:export\s{1,5})?[A-Z][A-Z0-9_]{0,100}\s{0,5}=\s{0,5})(\S.*)$/;
const ENV_COMMENT = /^\s{0,20}(?:\d{1,9}[→\t]\s{0,5})?#/;
const ENV_PATH = /(?:^|[/\\])(?:\.env(?:\.[\w.-]{1,40})?|\.envrc)$/;
const BASE64_BLOB = /^[A-Za-z0-9+/\r\n]{1000,}={0,2}$/;
const DATA_URI =
  /(data:[\w.+-]{1,64}\/[\w.+-]{1,64};base64,)[A-Za-z0-9+/=]{100,}/g;
const LONG_BASE64 = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{2000,}={0,2}/g;
/** JSON keys whose values are secrets whatever they look like. */
const SECRET_KEY =
  /(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|credentials?|token|cookie|authorization)$/i;

const bump = (counts: Counts, id: string, n = 1) => {
  if (n) counts[id] = (counts[id] ?? 0) + n;
};

function replaceCounting(
  s: string,
  re: RegExp,
  to: (g: string[]) => string,
  counts: Counts,
  id: string,
): string {
  let hits = 0;
  const out = s.replace(re, (...args: unknown[]) => {
    hits++;
    // Arguments are (match, ...groups, offset, input); the offset is the first number.
    const groups = args.slice(
      0,
      args.findIndex((a) => typeof a === "number"),
    );
    return to(groups.map((g) => (typeof g === "string" ? g : "")));
  });
  bump(counts, id, hits);
  return out;
}

/** Masks every value of a `.env` body, keeping the names so the analysis can still read them. */
function maskEnvBody(text: string, counts: Counts): string {
  const lines = text.split("\n");
  if (!lines.some((l) => ENV_LINE.test(l))) return text;
  bump(counts, "env-file");
  return lines
    .map((l) => (ENV_COMMENT.test(l) ? l : l.replace(ENV_LINE, "$1<REDACTED>")))
    .join("\n");
}

export function scrubText(
  text: string,
  counts: Counts,
  home?: string,
  envFile = false,
): string {
  if (BASE64_BLOB.test(text)) {
    bump(counts, "base64-blob");
    return "<base64 omitted>";
  }
  let s = envFile ? maskEnvBody(text, counts) : text;
  s = replaceCounting(
    s,
    DATA_URI,
    keep1("<base64 omitted>"),
    counts,
    "base64-blob",
  );
  s = replaceCounting(
    s,
    LONG_BASE64,
    fixed("<base64 omitted>"),
    counts,
    "base64-blob",
  );
  for (const rule of RULES)
    s = replaceCounting(s, rule.re, rule.to, counts, rule.id);
  s = scrubPersonalData(s, counts);
  return home ? rewriteHome(s, home, counts) : s;
}

/** Account names that are the same on every machine, so they identify no one. */
const GENERIC_USERS = new Set([
  "root", "admin", "administrator", "user", "users", "ubuntu", "runner", "guest", "test", "home",
  "developer", "ec2-user", "vagrant", "node", "default", "local", "owner", "staff", "codespace",
  "jenkins", "circleci", "azureuser", "postgres", "debian", "centos", "docker", "nobody",
  "www-data", "vscode", "gitpod", "coder", "build", "sandbox", "cloudshell-user",
]);

/**
 * Matches the account name where it stands alone, unless it is too short or generic to be
 * anyone's. `{USER}` replaces it: folder names carry it too, and Windows forbids `<` in them.
 */
function userPattern(home: string): RegExp | undefined {
  const user = home.split(/[/\\]/).pop() ?? "";
  if (user.length < 4 || GENERIC_USERS.has(user.toLowerCase())) return undefined;
  return new RegExp(`(?<![A-Za-z0-9])${escapeRe(user)}(?![A-Za-z0-9])`, "g");
}

function normalHome(home: string | undefined): string | undefined {
  const h = home?.replace(/[/\\]+$/, "");
  return h && h.length >= 2 ? h : undefined;
}

/**
 * The home path becomes `~`, and so does the form Claude Code uses in project folder names
 * (`-Users-pat-repo` becomes `~-repo`), so memory paths still match the uploaded folders.
 */
function rewriteHome(text: string, home: string, counts: Counts): string {
  const h = normalHome(home);
  if (!h) return text;
  let s = text;
  const forms: [string, string][] = [
    [h, "(?![A-Za-z0-9_-])"],
    [encodeProjectDir(h), "(?![A-Za-z0-9])"],
  ];
  for (const [form, boundary] of forms) {
    if (s.includes(form))
      s = replaceCounting(
        s,
        new RegExp(`${escapeRe(form)}${boundary}`, "g"),
        fixed("~"),
        counts,
        "home-path",
      );
  }
  // The account name also turns up outside the home folder (`/private/var/tmp/_bazel_<name>/`).
  const user = userPattern(h);
  return user ? replaceCounting(s, user, fixed("{USER}"), counts, "username") : s;
}

/** The upload folder name for a project: the user's home part replaced with `~`. */
export function aliasProjectDir(project: string, home?: string): string {
  const h = normalHome(home);
  if (!h) return project;
  const enc = encodeProjectDir(h);
  const aliased = project === enc || project.startsWith(`${enc}-`) ? `~${project.slice(enc.length)}` : project;
  const user = userPattern(h);
  return user ? aliased.replace(user, "{USER}") : aliased;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const INTERRUPT_MARKER = "[Request interrupted";

// Lines that state an error: the analyzer's own error markers plus the exception line a traceback ends on.
const ERROR_LINE =
  /^HTTP\/?\s?[45]\d\d|\b[45]\d\d Bad Gateway|^Traceback \(most recent call last\)|^\s*(?:Error|ERROR|FAILED|fatal|error)(?::|\[)|^(?:FAILED|ERROR) |command not found|No such file or directory|^[\w.]*(?:Error|Exception)\b:/;
// Free-form failure wording, for errors that follow no format (a timeout, a refused connection).
const ERROR_WORDS =
  /\b(?:errors?|failed|failure|exception|exceeded|timed? ?out|timeout|cannot|can't|could not|unable to|denied|not found|invalid|unexpected|refused)\b/i;
const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
const ERROR_MAX_LINES = 6;
const ERROR_LINE_CHARS = 200;
const ERROR_CHARS = 500;

/**
 * The few lines of a failed call's output that state the error: the first line (the analyzer groups
 * failures by it), lines that look like an error, and the last line, where most tools put the
 * summary. Everything else in the output is left out.
 */
export function errorMessage(output: string): string {
  const { lines, picked } = errorLines(output);
  return messageFrom(lines, picked);
}

/** A failed call's non-empty output lines, and the indexes the fixed rule picks as its error message. */
export function errorLines(output: string): { lines: string[]; picked: number[] } {
  const lines = output
    .replace(ANSI, "")
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l.trim() !== "");
  if (!lines.length) return { lines, picked: [] };
  const last = lines.length - 1;
  const formatted = lines.flatMap((l, i) => (i > 0 && i < last && ERROR_LINE.test(l) ? [i] : []));
  const worded = lines.flatMap((l, i) => (i > 0 && i < last && ERROR_WORDS.test(l) ? [i] : []));
  const middle = [...new Set([...formatted, ...worded])].slice(0, ERROR_MAX_LINES - 2);
  return { lines, picked: [...new Set([0, ...middle, last])].sort((a, b) => a - b) };
}

/** The message sent for the given line indexes: at most 6 lines and 500 characters. */
export function messageFrom(lines: string[], picked: number[]): string {
  const kept = [...new Set(picked)]
    .filter((i) => Number.isInteger(i) && i >= 0 && i < lines.length)
    .sort((a, b) => a - b)
    .slice(0, ERROR_MAX_LINES)
    .map((i) => lines[i] ?? "")
    .map((l) => (l.length > ERROR_LINE_CHARS ? `${l.slice(0, ERROR_LINE_CHARS)}…` : l));
  const message = kept.join("\n");
  return message.length > ERROR_CHARS ? `${message.slice(0, ERROR_CHARS)}…` : message;
}

/** A failed call's redacted output, kept only in the local preview so the plugin can pick its error lines. */
export interface ErrorCandidate {
  id: string;
  lines: string[];
  picked: number[];
}

// A model reads at most this many lines of one failed output: the head and the tail.
const CANDIDATE_HEAD = 150;
const CANDIDATE_TAIL = 100;

function candidateOf(id: string, lines: string[], picked: number[]): ErrorCandidate {
  if (lines.length <= CANDIDATE_HEAD + CANDIDATE_TAIL) return { id, lines, picked };
  const tailStart = lines.length - CANDIDATE_TAIL;
  const kept = [...lines.slice(0, CANDIDATE_HEAD), ...lines.slice(tailStart)];
  const remap = picked.flatMap((i) => (i < CANDIDATE_HEAD ? [i] : i >= tailStart ? [i - tailStart + CANDIDATE_HEAD] : []));
  return { id, lines: kept, picked: remap };
}

function outputText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((b) => (b && typeof b === "object" && typeof (b as { text?: unknown }).text === "string" ? (b as { text: string }).text : ""))
    .filter(Boolean)
    .join("\n");
}

function isImageBlock(v: Record<string, unknown>): boolean {
  const src = v.source as Record<string, unknown> | undefined;
  return (
    v.type === "image" &&
    typeof src === "object" &&
    src !== null &&
    typeof src.data === "string"
  );
}

function namesEnvFile(obj: Record<string, unknown> | undefined): boolean {
  if (!obj || typeof obj !== "object") return false;
  return [obj.filePath, obj.file_path].some(
    (p) => typeof p === "string" && ENV_PATH.test(p),
  );
}

/** True when this object, or the tool result it carries, is about a `.env` file. */
function aboutEnvFile(obj: Record<string, unknown>): boolean {
  const result = obj.toolUseResult as Record<string, unknown> | undefined;
  return (
    namesEnvFile(obj) ||
    namesEnvFile(result) ||
    namesEnvFile(result?.file as Record<string, unknown> | undefined)
  );
}

/**
 * A tool's output is never sent. A failed call keeps only its error message, redacted; every block
 * keeps its id and error flag, so the analyzer can pair the call with its result and count
 * failures, and an interruption keeps its marker.
 */
function withoutOutput(
  block: Record<string, unknown>,
  counts: Counts,
  home: string | undefined,
  envFile: boolean,
  errors?: ErrorCandidate[],
): Record<string, unknown> {
  const { content, ...rest } = block;
  const text = outputText(content);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rest)) out[k] = redactValue(v, counts, home, envFile, errors);
  if (text.startsWith(INTERRUPT_MARKER)) out.content = INTERRUPT_MARKER;
  else if (block.is_error === true) {
    // Scrubbed whole before lines are picked and cut, so a cut never splits a secret past its pattern.
    const { lines, picked } = errorLines(scrubText(text.replace(ANSI, ""), counts, home, envFile));
    out.content = messageFrom(lines, picked);
    if (errors && typeof block.tool_use_id === "string" && lines.length) {
      errors.push(candidateOf(block.tool_use_id, lines, picked));
    }
  } else out.content = "";
  return out;
}

/** A placeholder this redactor wrote, such as `<REDACTED>` or `<GITHUB_TOKEN>`. */
const PLACEHOLDER = /^<[A-Z][A-Z0-9_]*>$/;

/** Redacts every string and number under a secret-named key, at any depth, keeping the shape. */
function redactSecretValue(value: unknown, counts: Counts, home?: string): unknown {
  if (typeof value === "string" || typeof value === "number") {
    if (PLACEHOLDER.test(String(value))) return value;
    bump(counts, "secret-key");
    return "<REDACTED>";
  }
  if (Array.isArray(value)) return value.map((v) => redactSecretValue(v, counts, home));
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value).map(([k, v]) => [scrubText(k, counts, home), redactSecretValue(v, counts, home)]),
  );
}

export function redactValue(
  value: unknown,
  counts: Counts,
  home?: string,
  envFile = false,
  errors?: ErrorCandidate[],
): unknown {
  if (typeof value === "string") return scrubText(value, counts, home, envFile);
  if (Array.isArray(value))
    return value.map((v) => redactValue(v, counts, home, envFile, errors));
  if (typeof value !== "object" || value === null) return value;
  const obj = value as Record<string, unknown>;
  if (obj.type === "tool_result") return withoutOutput(obj, counts, home, envFile, errors);
  if (isImageBlock(obj)) {
    bump(counts, "image");
    const source = obj.source as Record<string, unknown>;
    return { ...obj, source: { ...source, data: "<image omitted>" } };
  }
  const env = envFile || aboutEnvFile(obj);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    // Claude Code's structured duplicate of the tool_result in `message`.
    if (k === "toolUseResult") continue;
    const key = scrubText(k, counts, home);
    out[key] = SECRET_KEY.test(k) ? redactSecretValue(v, counts, home) : redactValue(v, counts, home, env, errors);
  }
  return out;
}

/**
 * Redacts one JSONL line. Returns undefined for a line that is not JSON (a torn line at the end
 * of a live session): it is dropped rather than uploaded unscrubbed.
 */
export function redactLine(
  line: string,
  counts: Counts,
  home?: string,
  errors?: ErrorCandidate[],
): string | undefined {
  if (!line.trim()) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    bump(counts, "unparsable-line");
    return undefined;
  }
  return JSON.stringify(redactValue(parsed, counts, home, false, errors));
}

export function redactJsonl(
  text: string,
  counts: Counts,
  home?: string,
): string {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const r = redactLine(line, counts, home);
    if (r !== undefined) out.push(r);
  }
  return out.length ? `${out.join("\n")}\n` : "";
}

/** For `*.meta.json` and other single-document JSON files in a session folder. */
export function redactJson(
  text: string,
  counts: Counts,
  home?: string,
): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    bump(counts, "unparsable-file");
    return "{}";
  }
  return JSON.stringify(redactValue(parsed, counts, home));
}

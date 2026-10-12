import { execFileSync, spawn } from "node:child_process";
import { existsSync, openAsBlob } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs, type ParseArgsConfig } from "node:util";
import {
  Client,
  configDir,
  DEFAULT_API,
  FINAL_PHASES,
  ISSUES_URL,
  type Recommendation,
  type Recommendations,
  type RunStatus,
  type Sharing,
} from "./api.js";
import { Auth, type PendingLogin, SignInError } from "./auth.js";
import { collect, defaultProjectsDir, utcToday } from "./collect.js";
import { buildManifest, LIMITS, limitProblem, pack } from "./pack.js";
import { humanSize, type PreviewMeta, readPreview, REPORT_FILE, writePreview } from "./preview.js";

export interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
}

export interface Env {
  io: Io;
  version: string;
  cwd: string;
  env: NodeJS.ProcessEnv;
  isTTY: boolean;
  ask: (question: string) => Promise<boolean>;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  configDir?: string;
  /** Opens a URL in the user's browser; defaults to the platform's opener. */
  openUrl?: (url: string) => void;
}

/** Wrong flags or arguments: shown with the usage text, exit code 2. */
export class UsageError extends Error {}

/** A problem the user can fix, shown as-is, exit code 1. */
export class UserError extends Error {}

/** Exit codes: 0 done, 1 failed, 2 bad usage, 3 the run is still going. */
export const STILL_RUNNING = 3;

const SCOPE_OPTIONS = {
  days: { type: "string" },
  "all-projects": { type: "boolean" },
  "exclude-session": { type: "string", multiple: true },
} as const satisfies ParseArgsConfig["options"];

const API_OPTION = { api: { type: "string" } } as const satisfies ParseArgsConfig["options"];

function parse<O extends NonNullable<ParseArgsConfig["options"]>>(args: string[], options: O, positionals = 0) {
  let parsed;
  try {
    parsed = parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
  if (parsed.positionals.length !== positionals) {
    throw new UsageError(
      positionals === 0
        ? `Unexpected argument: ${parsed.positionals[0]}`
        : `Expected ${positionals} argument${positionals > 1 ? "s" : ""}, got ${parsed.positionals.length}.`,
    );
  }
  return parsed;
}

/** The repository the user is in, so sessions started anywhere inside it count as this project. */
export function projectRoot(cwd: string): string {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return cwd; // Not a git repository (or git isn't installed): the folder itself is the project.
  }
}

/** Transcripts only ever go over HTTPS, except to a server on this machine. */
function apiBase(e: Env, api?: string): string {
  const raw = api ?? e.env.REVEFI_ANALYZER_API ?? DEFAULT_API;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UsageError(`${raw} isn't a valid server URL.`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new UsageError(`The server must use https:// (got ${raw}).`);
  }
  return raw;
}

/**
 * Each server gets its own sign-in, so a repository that points the CLI at another server never
 * receives the refresh token for the default one.
 */
function serverDir(e: Env, base: string): string {
  const root = e.configDir ?? configDir(e.env);
  const host = new URL(base).host;
  return host === new URL(DEFAULT_API).host ? root : join(root, "servers", host.replace(/[^\w.-]/g, "_"));
}

const loginCommand = (api?: string) => `revefi-agent-analyzer login${api ? ` --api ${quote(api)}` : ""}`;

function auth(e: Env, api?: string): Auth {
  const base = apiBase(e, api);
  return new Auth({ base, dir: serverDir(e, base), fetch: e.fetch, sleep: e.sleep, env: e.env, loginCommand: loginCommand(api) });
}

/** Opens the sign-in page without a shell, so the URL is never interpreted as a command. */
function openInBrowser(url: string): void {
  // Over SSH with no display, xdg-open can start a text browser nobody sees.
  if (process.platform === "linux" && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) return;
  const [cmd, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
        : ["xdg-open", [url]];
  const child = spawn(cmd, args, { stdio: "ignore", detached: true, windowsHide: true });
  // The printed link is the fallback, so a missing opener is not an error.
  child.on("error", () => undefined);
  child.unref();
}

function describeLogin(e: Env, p: PendingLogin): void {
  e.io.err(`Open this link to sign in:\n  ${p.verification_uri_complete}`);
  e.io.err(`Check that the page shows the code ${p.user_code}, then continue with Google or an emailed code.`);
}

function client(e: Env, api?: string, a: Auth = auth(e, api)): Client {
  return new Client({
    base: apiBase(e, api),
    token: (force) => a.accessToken(force),
    loginCommand: loginCommand(api),
    userAgent: `revefi-agent-analyzer/${e.version}`,
    fetch: e.fetch,
    sleep: e.sleep,
    env: e.env,
  });
}

/** Starts a device login, shows the link (opening it when asked) and waits for approval. */
async function signIn(e: Env, a: Auth, openBrowser: boolean, timeoutMs?: number): Promise<string | null> {
  const pending = await a.startLogin();
  describeLogin(e, pending);
  if (openBrowser) (e.openUrl ?? openInBrowser)(pending.verification_uri_complete);
  return (await a.finishLogin({ timeoutMs })).email;
}

/**
 * Checks the sign-in still works (renewing it if needed); in a terminal, signs in on the spot
 * when that is what's missing, otherwise the caller gets the error.
 */
async function ensureSignedIn(e: Env, a: Auth): Promise<void> {
  try {
    await a.accessToken();
    return;
  } catch (err) {
    if (!(err instanceof SignInError) || err.reason !== "signed_out" || !e.isTTY) throw err;
  }
  const email = await signIn(e, a, true);
  e.io.err(email ? `Signed in as ${email}.` : "Signed in.");
}

function wholeNumber(raw: string | undefined, flag: string, fallback: number, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (raw === undefined) return fallback;
  const n = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!(n >= min && n <= max)) {
    throw new UsageError(max === Number.MAX_SAFE_INTEGER ? `${flag} must be a whole number of at least ${min}.` : `${flag} must be a whole number from ${min} to ${max}.`);
  }
  return n;
}

const quote = (p: string) => (/^[\w./~-]+$/.test(p) ? p : `"${p.replace(/(["\\$`])/g, "\\$1")}"`);

const COUNT_LABELS: Record<string, [string, string]> = {
  "private-key": ["private key", "private keys"],
  "anthropic-key": ["Anthropic key", "Anthropic keys"],
  "openai-key": ["OpenAI key", "OpenAI keys"],
  "github-token": ["GitHub token", "GitHub tokens"],
  "gitlab-token": ["GitLab token", "GitLab tokens"],
  "aws-access-key": ["AWS key ID", "AWS key IDs"],
  "aws-secret-key": ["AWS secret key", "AWS secret keys"],
  "slack-token": ["Slack token", "Slack tokens"],
  "stripe-key": ["Stripe key", "Stripe keys"],
  "google-api-key": ["Google API key", "Google API keys"],
  jwt: ["JWT", "JWTs"],
  "auth-header": ["authorization header", "authorization headers"],
  "cookie-header": ["cookie header", "cookie headers"],
  "bearer-token": ["bearer token", "bearer tokens"],
  "url-credentials": ["password in a URL", "passwords in URLs"],
  "cli-password": ["command-line password", "command-line passwords"],
  "secret-assignment": ["named secret", "named secrets"],
  "secret-key": ["secret field", "secret fields"],
  "env-file": [".env file", ".env files"],
  image: ["image", "images"],
  email: ["email address", "email addresses"],
  phone: ["phone number", "phone numbers"],
  "card-number": ["card number", "card numbers"],
  iban: ["IBAN", "IBANs"],
  ssn: ["Social Security number", "Social Security numbers"],
  "national-id": ["national ID number", "national ID numbers"],
  "upi-id": ["UPI ID", "UPI IDs"],
  "ip-address": ["IP address", "IP addresses"],
};

function redactionLine(meta: PreviewMeta): string {
  const named = Object.entries(meta.counts).filter(([id]) => COUNT_LABELS[id]);
  const other = Object.entries(meta.counts)
    .filter(([id]) => !COUNT_LABELS[id] && id !== "home-path" && id !== "username" && !id.startsWith("unparsable"))
    .reduce((a, [, n]) => a + n, 0);
  const parts = named.sort(([, a], [, b]) => b - a).map(([id, n]) => `${n} ${COUNT_LABELS[id]?.[n === 1 ? 0 : 1]}`);
  if (other) parts.push(`${other} other secret${other === 1 ? "" : "s"} or blobs`);
  return parts.length ? `Removed: ${parts.join(", ")}` : "No known secrets or personal data found.";
}

interface Prepared {
  dir: string;
  meta: PreviewMeta;
  sourceBytes: number;
  scope: string;
}

/** The server a preview was shown as going to; `upload` refuses to send it anywhere else. */
const UPLOAD_TO = "upload_to";

async function checkHost(dir: string, base: string): Promise<void> {
  const file = join(dir, UPLOAD_TO);
  const recorded = existsSync(file) ? (await readFile(file, "utf8")).trim() : "";
  const host = new URL(base).host;
  if (recorded && recorded !== host) {
    throw new UserError(`This preview was prepared for ${recorded}, not ${host}. Run \`prepare\` again for ${host}, or pass --api for ${recorded}.`);
  }
}

async function prepareFrom(
  e: Env,
  values: { days?: string; "all-projects"?: boolean; "exclude-session"?: string[]; api?: string },
): Promise<Prepared> {
  const days = wholeNumber(values.days, "--days", LIMITS.maxDays, 1, LIMITS.maxDays);
  const root = projectRoot(e.cwd);
  const projectsDir = defaultProjectsDir(e.env);
  const all = Boolean(values["all-projects"]);
  const { window, sessions } = await collect({
    projectsDir,
    root: all ? undefined : root,
    days,
    today: utcToday(),
    exclude: values["exclude-session"],
  });
  const empty = limitProblem({ window, session_count: sessions.length, bytes: { compressed: 0, uncompressed: 0 } });
  if (empty) throw new UserError(empty);
  const { dir, meta } = await writePreview({ projectsDir, window, sessions, revefiDir: join(root, ".revefi"), home: homedir() });
  await writeFile(join(dir, UPLOAD_TO), `${new URL(apiBase(e, values.api)).host}\n`, { mode: 0o600 });
  return { dir, meta, sourceBytes: sessions.reduce((a, s) => a + s.bytes, 0), scope: all ? "all projects on this machine" : root };
}

function describePreview(e: Env, p: { dir: string; meta: PreviewMeta; sourceBytes?: number; scope?: string }, api: string): void {
  const { meta } = p;
  const size = p.sourceBytes === undefined ? humanSize(meta.bytes) : `${humanSize(p.sourceBytes)} → ${humanSize(meta.bytes)} after redaction`;
  const projects = new Set(meta.sessions.map((s) => s.project)).size;
  if (p.scope) e.io.out(`Scope: ${p.scope}`);
  e.io.out(`${meta.sessions.length} sessions in ${projects} project${projects === 1 ? "" : "s"}, ${meta.window.start} to ${meta.window.end} · ${size}`);
  e.io.out(redactionLine(meta));
  e.io.out(`Preview: ${relative(e.cwd, p.dir) || "."}  (${REPORT_FILE} there lists exactly what is sent)`);
  e.io.out("");
  e.io.out(`This uploads the redacted transcripts in the preview to ${new URL(api).host} for analysis.`);
}

async function consent(e: Env, values: { yes?: boolean; json?: boolean }, dir: string): Promise<boolean> {
  if (values.yes) return true;
  if (values.json || !e.isTTY) {
    e.io.err(
      `Nothing was uploaded: there is no terminal here to confirm it. Review ${quote(join(relative(e.cwd, dir) || ".", REPORT_FILE))}, ` +
        `then run \`revefi-agent-analyzer upload ${quote(relative(e.cwd, dir) || ".")}\` in a terminal.`,
    );
    return false;
  }
  if (await e.ask("Upload? [y/N] ")) return true;
  e.io.err(`Nothing was uploaded. The preview stays in ${quote(relative(e.cwd, dir) || ".")} until you delete it.`);
  return false;
}

function clientName(e: Env): "plugin" | "cli" {
  return e.env.CLAUDECODE ? "plugin" : "cli";
}

/** Only folders `prepare` made are deleted after upload, whatever path the user passes. */
function isPreviewFolder(dir: string): boolean {
  return basename(dirname(dir)) === "upload-preview" && basename(dirname(dirname(dir))) === ".revefi";
}

interface Started {
  c: Client;
  runId: string;
  reportUrl: string;
  status: RunStatus;
}

async function uploadPreview(e: Env, dir: string, api?: string, a: Auth = auth(e, api)): Promise<Started> {
  const meta = await readPreview(dir);
  await checkHost(dir, apiBase(e, api));
  await ensureSignedIn(e, a);
  const archive = join(dir, "upload.tar.gz");
  try {
    const packed = await pack(dir, meta, archive);
    const manifest = buildManifest(meta, packed, { name: clientName(e), version: e.version });
    const problem = limitProblem(manifest);
    if (problem) throw new UserError(problem);
    const c = client(e, api, a);
    e.io.err(`Uploading ${humanSize(packed.compressed)}...`);
    const run = await c.createRun(manifest);
    await c.upload(run.upload, await openAsBlob(archive));
    const status = await c.complete(run.run_id);
    const reportUrl = c.link(run.report_url);
    e.io.err(`Run ${run.run_id} started. Report: ${reportUrl}`);
    if (isPreviewFolder(dir)) await rm(dir, { recursive: true, force: true });
    return { c, runId: run.run_id, reportUrl, status };
  } finally {
    await rm(archive, { force: true });
  }
}

const PHASE_COPY: Record<string, string> = {
  uploading: "Waiting for the upload",
  analyzing: "Analyzing",
  finishing: "Building the report",
};

const usd = (n: number) => `$${n >= 100 ? Math.round(n).toLocaleString("en-US") : n.toFixed(2)}`;

function topRecommendations(recs: Recommendations, n = 3): Recommendation[] {
  return recs.recommendations
    .filter((r) => r.verdict === "optimizable")
    .sort((a, b) => b.cluster.window_usd - a.cluster.window_usd)
    .slice(0, n);
}

function printSummary(e: Env, recs: Recommendations): void {
  const optimizable = recs.recommendations.filter((r) => r.verdict === "optimizable");
  if (optimizable.length === 0) {
    e.io.out("No repeated tasks worth fixing were found in this window.");
    return;
  }
  const total = optimizable.reduce((a, r) => a + r.cluster.window_usd, 0);
  e.io.out(`≈ ${usd(total)} went to ${optimizable.length} repeated tasks in this window (at API pricing).`);
  topRecommendations(recs).forEach((r, i) => e.io.out(`  ${i + 1}. ${r.title}  ≈ ${usd(r.cluster.window_usd)}  (${r.id})`));
}

/** The one JSON shape every run-reporting command prints. */
function runJson(runId: string, reportUrl: string, s: Pick<RunStatus, "phase" | "percent" | "cost_capped">, recs?: Recommendations) {
  return JSON.stringify({
    run_id: runId,
    report_url: reportUrl,
    phase: s.phase,
    percent: s.percent,
    cost_capped: s.cost_capped,
    top: recs ? topRecommendations(recs) : [],
  });
}

function finish(e: Env, s: RunStatus, runId: string): number {
  if (s.phase === "done") return 0;
  if (s.phase === "deferred") {
    e.io.err("The analyzer is at capacity and deferred this run. Try again tomorrow.");
    return 1;
  }
  if (s.phase === "failed") {
    e.io.err(`The analysis failed on the server. Try again; if it fails again, report run ${runId} at ${ISSUES_URL}.`);
    return 1;
  }
  e.io.err(`Still ${(PHASE_COPY[s.phase] ?? s.phase).toLowerCase()} (${s.percent}%). Check later with:\n  revefi-agent-analyzer status ${runId} --wait`);
  return STILL_RUNNING;
}

async function follow(e: Env, run: Omit<Started, "status">, timeoutSec: number, json: boolean): Promise<number> {
  let s: RunStatus;
  let recs: Recommendations | undefined;
  try {
    let last = "";
    s = await run.c.waitForRun(run.runId, {
      timeoutMs: timeoutSec * 1000,
      onProgress: (st) => {
        const line = `${PHASE_COPY[st.phase] ?? st.phase}... ${st.percent}%`;
        if (line !== last && !FINAL_PHASES.includes(st.phase)) e.io.err(line);
        last = line;
      },
    });
    recs = s.phase === "done" ? await run.c.recommendations(run.runId) : undefined;
  } catch (err) {
    throw new UserError(`${(err as Error).message}\nThe run was started; check it later with: revefi-agent-analyzer status ${run.runId} --wait`);
  }
  if (json) {
    e.io.out(runJson(run.runId, run.reportUrl, s, recs));
    return finish(e, s, run.runId);
  }
  e.io.out("");
  e.io.out(`Report: ${run.reportUrl}`);
  if (s.cost_capped) e.io.out("The analysis reached its cost limit, so the report covers a sample of these sessions.");
  if (recs) printSummary(e, recs);
  e.io.out(`Run id: ${run.runId}  (for status, share, feedback)`);
  return finish(e, s, run.runId);
}

export const COMMANDS: Record<string, { summary: string; run: (args: string[], e: Env) => Promise<number> }> = {
  login: {
    summary: "Sign in with Google or an emailed code (--start and --wait split it in two, for scripts)",
    async run(args, e) {
      const { values } = parse(args, {
        ...API_OPTION,
        start: { type: "boolean" },
        wait: { type: "boolean" },
        json: { type: "boolean" },
        "no-browser": { type: "boolean" },
        timeout: { type: "string" },
      });
      if (values.start && values.wait) throw new UsageError("Use --start or --wait, not both.");
      const a = auth(e, values.api);
      if (values.start) {
        const pending = await a.startLogin();
        if (values.json) {
          e.io.out(
            JSON.stringify({
              verification_uri_complete: pending.verification_uri_complete,
              user_code: pending.user_code,
              expires_in: Math.round((pending.expires_at - Date.now()) / 1000),
            }),
          );
        } else {
          describeLogin(e, pending);
          e.io.err(`Then run: ${loginCommand(values.api)} --wait`);
        }
        return 0;
      }
      const timeout = values.timeout === undefined ? undefined : wholeNumber(values.timeout, "--timeout", 0, 1) * 1000;
      const email = values.wait
        ? (await a.finishLogin({ timeoutMs: timeout })).email
        : await signIn(e, a, e.isTTY && !values["no-browser"], timeout);
      if (values.json) e.io.out(JSON.stringify({ email }));
      else e.io.out(email ? `Signed in as ${email}.` : "Signed in.");
      return 0;
    },
  },
  logout: {
    summary: "Sign out on this computer",
    async run(args, e) {
      const { values } = parse(args, API_OPTION);
      const { signedIn, revoked } = await auth(e, values.api).logout();
      if (!signedIn) e.io.out("You weren't signed in.");
      else if (revoked) e.io.out("Signed out.");
      else e.io.out("Signed out on this computer. The session couldn't be ended on the server; it expires on its own.");
      return 0;
    },
  },
  whoami: {
    summary: "Show who you're signed in as",
    async run(args, e) {
      const { values } = parse(args, { ...API_OPTION, json: { type: "boolean" } });
      const email = await auth(e, values.api).email();
      e.io.out(values.json ? JSON.stringify({ email }) : email ? `Signed in as ${email}.` : "Signed in (email unavailable).");
      return 0;
    },
  },
  analyze: {
    summary: "Collect, redact, preview, upload and wait for the report (asks before uploading)",
    async run(args, e) {
      const { values } = parse(args, { ...SCOPE_OPTIONS, ...API_OPTION, yes: { type: "boolean", short: "y" }, timeout: { type: "string" } });
      const timeout = wholeNumber(values.timeout, "--timeout", 30 * 60, 0);
      const api = apiBase(e, values.api);
      const a = auth(e, values.api);
      // In a terminal, sign in before the preview so the upload never stops for it; elsewhere the
      // upload step reports a missing sign-in.
      if (e.isTTY) await ensureSignedIn(e, a);
      const p = await prepareFrom(e, values);
      describePreview(e, p, api);
      if (!(await consent(e, values, p.dir))) return 1;
      return follow(e, await uploadPreview(e, p.dir, values.api, a), timeout, false);
    },
  },
  prepare: {
    summary: "Collect and redact sessions into a local preview folder; uploads nothing",
    async run(args, e) {
      const { values } = parse(args, { ...SCOPE_OPTIONS, ...API_OPTION, json: { type: "boolean" } });
      const api = apiBase(e, values.api);
      const p = await prepareFrom(e, values);
      if (values.json) {
        e.io.out(
          JSON.stringify({
            preview_dir: p.dir,
            report: join(p.dir, REPORT_FILE),
            scope: p.scope,
            window: p.meta.window,
            sessions: p.meta.sessions.length,
            session_list: p.meta.sessions.map((s) => ({ id: s.id, project: s.project, day: s.day, bytes: s.bytes })),
            bytes_before: p.sourceBytes,
            bytes_after: p.meta.bytes,
            redactions: p.meta.counts,
            upload_to: new URL(api).host,
          }),
        );
      } else {
        describePreview(e, p, api);
        e.io.out(`Upload it with: revefi-agent-analyzer upload ${quote(relative(e.cwd, p.dir))}`);
      }
      return 0;
    },
  },
  upload: {
    summary: "Upload a prepared preview folder and wait for the report",
    async run(args, e) {
      const { values, positionals } = parse(
        args,
        { ...API_OPTION, yes: { type: "boolean", short: "y" }, json: { type: "boolean" }, "no-wait": { type: "boolean" }, timeout: { type: "string" } },
        1,
      );
      const timeout = wholeNumber(values.timeout, "--timeout", 480, 0);
      const api = apiBase(e, values.api);
      const dir = resolve(e.cwd, positionals[0] ?? "");
      const meta = await readPreview(dir);
      if (!values.json) describePreview(e, { dir, meta }, api);
      if (!(await consent(e, values, dir))) return 1;
      const run = await uploadPreview(e, dir, values.api);
      if (values["no-wait"]) {
        if (values.json) e.io.out(runJson(run.runId, run.reportUrl, run.status));
        else e.io.out(`Follow it with: revefi-agent-analyzer status ${run.runId} --wait`);
        return 0;
      }
      return follow(e, run, timeout, Boolean(values.json));
    },
  },
  status: {
    summary: "Show a run's progress; --wait follows it until the report is ready",
    async run(args, e) {
      const { values, positionals } = parse(args, { ...API_OPTION, wait: { type: "boolean" }, json: { type: "boolean" }, timeout: { type: "string" } }, 1);
      const timeout = wholeNumber(values.timeout, "--timeout", 480, 0);
      const runId = positionals[0] ?? "";
      const c = client(e, values.api);
      const s = await c.status(runId);
      const reportUrl = c.link(s.report_url);
      if (values.wait) return follow(e, { c, runId, reportUrl }, timeout, Boolean(values.json));
      e.io.out(values.json ? runJson(runId, reportUrl, s) : `${PHASE_COPY[s.phase] ?? s.phase} ${s.percent}%  ${reportUrl}`);
      return 0;
    },
  },
  recommendations: {
    summary: "Print a finished run's recommendations (--json for the full list)",
    async run(args, e) {
      const { values, positionals } = parse(args, { ...API_OPTION, json: { type: "boolean" } }, 1);
      const recs = await client(e, values.api).recommendations(positionals[0] ?? "");
      if (values.json) e.io.out(JSON.stringify(recs));
      else printSummary(e, recs);
      return 0;
    },
  },
  feedback: {
    summary: "Rate a recommendation: feedback <run> <recommendation> up|down [--applied-pr URL]",
    async run(args, e) {
      const { values, positionals } = parse(args, { ...API_OPTION, "applied-pr": { type: "string" } }, 3);
      const [runId = "", recId = "", verdict = ""] = positionals;
      if (verdict !== "up" && verdict !== "down") throw new UsageError("The rating must be up or down.");
      const pr = values["applied-pr"];
      await client(e, values.api).feedback(runId, recId, pr ? { verdict, source: "skill", applied_pr_url: pr } : { verdict, source: "user" });
      e.io.out(pr ? "Recorded the applied fix. Thanks." : "Thanks, your rating was recorded.");
      return 0;
    },
  },
  share: {
    summary: "Show or change who can open a run's report: share <run> [--add EMAIL] [--remove EMAIL] [--link on|off]",
    async run(args, e) {
      const { values, positionals } = parse(
        args,
        { ...API_OPTION, add: { type: "string", multiple: true }, remove: { type: "string", multiple: true }, link: { type: "string" }, json: { type: "boolean" } },
        1,
      );
      const runId = positionals[0] ?? "";
      if (values.link !== undefined && values.link !== "on" && values.link !== "off") {
        throw new UsageError("--link must be on (anyone signed in with the link) or off.");
      }
      const add = (values.add ?? []).map((email) => email.trim().toLowerCase());
      const bad = add.find((email) => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email));
      if (bad) throw new UsageError(`${bad} isn't an email address.`);
      const c = client(e, values.api);
      let sharing = await c.sharing(runId);
      const remove = new Set((values.remove ?? []).map((email) => email.trim().toLowerCase()));
      const next: Sharing = {
        link: values.link === undefined ? sharing.link : values.link === "on",
        emails: [...new Set([...sharing.emails, ...add])].filter((email) => !remove.has(email)),
      };
      if (add.length || remove.size || values.link !== undefined) sharing = await c.setSharing(runId, next);
      const { report_url } = await c.status(runId);
      if (values.json) {
        e.io.out(JSON.stringify({ ...sharing, report_url: c.link(report_url) }));
        return 0;
      }
      e.io.out(sharing.emails.length ? `Shared with: ${sharing.emails.join(", ")}` : "Not shared with anyone by email.");
      e.io.out(sharing.link ? "Anyone signed in who has the link can open it." : "The link alone doesn't give access.");
      e.io.out(`Report: ${c.link(report_url)}`);
      return 0;
    },
  },
  "delete-my-data": {
    summary: "Delete every run, upload and report made with your account",
    async run(args, e) {
      const { values } = parse(args, { ...API_OPTION, yes: { type: "boolean", short: "y" } });
      const a = auth(e, values.api);
      const email = (await a.email()) ?? "your account";
      if (!values.yes) {
        if (!e.isTTY) {
          e.io.err(`Nothing was deleted. Run again with --yes to delete every run, upload and report made with ${email}.`);
          return 1;
        }
        if (!(await e.ask(`Delete every run, upload and report made with ${email}? This can't be undone. [y/N] `))) {
          e.io.err("Nothing was deleted.");
          return 1;
        }
      }
      await client(e, values.api, a).deleteMyData();
      e.io.out(`Deleted every run, upload and report made with ${email}. Local previews in .revefi/ are untouched.`);
      return 0;
    },
  },
};

export async function askYesNo(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return /^y(es)?$/i.test((await rl.question(question)).trim());
  } catch (err) {
    if ((err as Error).name === "AbortError") return false; // Ctrl-C at the prompt means no.
    throw err;
  } finally {
    rl.close();
  }
}

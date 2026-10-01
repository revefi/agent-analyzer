import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import type { Manifest } from "./pack.js";

export const DEFAULT_API = "https://analyzer.revefi.com";
export const ISSUES_URL = "https://github.com/revefi/agent-analyzer/issues";

export type Phase = "uploading" | "analyzing" | "finishing" | "done" | "failed" | "deferred";
export const FINAL_PHASES: readonly Phase[] = ["done", "failed", "deferred"];

export interface UploadTarget {
  url: string;
  method?: string;
  headers: Record<string, string>;
  expires_at: string;
}

export interface CreatedRun {
  run_id: string;
  report_url: string;
  upload: UploadTarget;
}

export interface RunStatus {
  run_id: string;
  phase: Phase;
  percent: number;
  cost_capped: boolean;
  report_url: string;
}

export interface Recommendation {
  id: string;
  title: string;
  verdict: "optimizable" | "already_lean";
  description: string;
  cluster: { label: string; occurrences: number; sessions: number; window_usd: number };
  estimated_savings: { window_usd: number; annualized_usd: number } | null;
  fix_prompt: string;
  fixes: { letter: string; type: string; title: string; text: string }[];
}

export interface Recommendations {
  run_id: string;
  contract_version: number;
  generated_at: string;
  window: { days: number; start: string; end: string };
  recommendations: Recommendation[];
  root_causes: { id: string; title: string; window_usd: number; annualized_usd: number }[];
}

export interface Feedback {
  verdict: "up" | "down";
  source: "user" | "skill";
  applied_pr_url?: string;
}

/** An error whose message is meant for the person running the CLI. */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function configDir(env: NodeJS.ProcessEnv = process.env): string {
  // The XDG spec says a relative XDG_CONFIG_HOME is invalid and must be ignored.
  const xdg = env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : undefined;
  const base = xdg || (process.platform === "win32" && env.APPDATA) || join(homedir(), ".config");
  return join(base, "revefi", "agent-analyzer");
}

const MACHINE_ID = /^[0-9a-f]{32,128}$/;

/**
 * A random id for this machine, created once. The server stores only a keyed hash of it, and it
 * is the only way back to this machine's runs, so it is never silently replaced.
 */
export async function loadMachineId(dir: string = configDir()): Promise<string> {
  const file = join(dir, "machine-id");
  const id = randomBytes(32).toString("hex");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    await writeFile(file, `${id}\n`, { flag: "wx", mode: 0o600 });
    return id;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }
  await chmod(file, 0o600);
  const existing = (await readFile(file, "utf8")).trim();
  if (MACHINE_ID.test(existing)) return existing;
  throw new ApiError(
    `${file} is damaged. Restore it from a backup, or delete it to start over as a new machine ` +
      "(you would lose access to reports made from this machine so far).",
  );
}

export interface ClientOptions {
  base: string;
  machineId: string;
  userAgent: string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  env?: NodeJS.ProcessEnv;
}

interface Call {
  method: string;
  path: string;
  body?: unknown;
  auth?: boolean;
  /** False when repeating the call after a lost response could create a second record. */
  idempotent?: boolean;
  /** Copy for a 409 on this call, which means different things on different routes. */
  conflict?: string;
  /** Copy for a 404 on this call; defaults to the server's own detail. */
  notFound?: string;
}

const MAX_RETRY_WAIT_MS = 60_000;
const CALL_TIMEOUT_MS = 30_000;
const RUN_NOT_FOUND = "Run not found. Runs can only be managed from the machine that uploaded them, and deleted runs are gone.";

/** Ends a sentence once, whether or not the server's text already did. */
const sentence = (s: string) => (/[.!?]$/.test(s.trim()) ? s.trim() : `${s.trim()}.`);

export class Client {
  private token?: string;
  private readonly fetch: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly env: NodeJS.ProcessEnv;
  readonly base: string;

  constructor(private readonly opts: ClientOptions) {
    this.base = opts.base.replace(/\/+$/, "");
    this.fetch = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.env = opts.env ?? process.env;
  }

  /** Absolute URL for a server-relative link such as a run's `report_url`. */
  link(path: string): string {
    return new URL(path, `${this.base}/`).toString();
  }

  /** Never echoes the URL or the raw error: an upload URL carries a signature. */
  private async send(url: string, init: RequestInit, host: string): Promise<Response> {
    try {
      return await this.fetch(url, init);
    } catch (err) {
      const e = err as Error & { cause?: { code?: string; message?: string } };
      if (e.name === "TimeoutError") {
        throw new ApiError(`${host} didn't respond in time. Try again in a few minutes.`);
      }
      const why = e.cause?.code ?? e.cause?.message ?? e.message;
      const proxied = (this.env.HTTPS_PROXY || this.env.https_proxy) && !this.env.NODE_USE_ENV_PROXY;
      const hint = proxied ? " You have HTTPS_PROXY set; Node uses it only when NODE_USE_ENV_PROXY=1 is also set." : "";
      throw new ApiError(`Couldn't reach ${host} (${why}). Check your connection and try again.${hint}`);
    }
  }

  private async deviceToken(): Promise<string> {
    if (!this.token) {
      const res = await this.call<{ device_token: string }>({
        method: "POST",
        path: "/api/device",
        body: { machine_id: this.opts.machineId },
        auth: false,
      });
      this.token = res.device_token;
    }
    return this.token;
  }

  private async call<T>(c: Call, attempt = 0, refreshed = false): Promise<T> {
    const headers: Record<string, string> = { "user-agent": this.opts.userAgent, accept: "application/json" };
    if (c.body !== undefined) headers["content-type"] = "application/json";
    if (c.auth !== false) headers.authorization = `Bearer ${await this.deviceToken()}`;
    const res = await this.send(
      `${this.base}${c.path}`,
      {
        method: c.method,
        headers,
        body: c.body === undefined ? undefined : JSON.stringify(c.body),
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
      },
      new URL(this.base).host,
    );
    if (res.ok) return (res.status === 204 ? undefined : await res.json()) as T;

    const detail = await errorDetail(res);
    const wait = retryDelayMs(res, attempt, c.idempotent !== false);
    if (wait !== undefined && attempt < 2) {
      await this.sleep(wait);
      return this.call(c, attempt + 1, refreshed);
    }
    if (res.status === 401 && c.auth !== false && !refreshed) {
      this.token = undefined;
      return this.call(c, attempt, true);
    }
    throw new ApiError(explain(res, detail, c), res.status);
  }

  createRun(manifest: Manifest): Promise<CreatedRun> {
    return this.call({ method: "POST", path: "/api/runs", body: manifest, idempotent: false });
  }

  /** PUTs the archive to the presigned URL; the signed headers must be sent exactly as given. */
  async upload(target: UploadTarget, body: Blob): Promise<void> {
    const declared = Object.entries(target.headers).find(([k]) => k.toLowerCase() === "content-length")?.[1];
    if (declared !== undefined && Number(declared) !== body.size) {
      throw new ApiError("The archive changed after it was packed. Run the command again.");
    }
    // At least two minutes, plus time for a slow (50 KB/s) connection.
    const timeout = Math.max(120_000, (body.size / 50_000) * 1000);
    const res = await this.send(
      target.url,
      { method: target.method ?? "PUT", headers: target.headers, body, signal: AbortSignal.timeout(timeout) },
      "storage",
    );
    if (res.ok) return;
    const code = (await res.text()).match(/<Code>([A-Za-z]{1,64})<\/Code>/)?.[1];
    const expired = res.status === 403 && Date.parse(target.expires_at) < Date.now();
    const next = expired
      ? "The upload link expired. Run the command again."
      : res.status === 403
        ? `Update the CLI, and if that doesn't help, report it at ${ISSUES_URL}.`
        : "Run the command again.";
    throw new ApiError(`Storage rejected the upload (HTTP ${res.status}${code ? `, ${code}` : ""}). ${next}`, res.status);
  }

  complete(runId: string): Promise<RunStatus> {
    return this.call({
      method: "POST",
      path: `/api/runs/${encodeURIComponent(runId)}/complete`,
      conflict: "The server didn't receive the upload. Run the command again.",
      notFound: RUN_NOT_FOUND,
    });
  }

  status(runId: string): Promise<RunStatus> {
    return this.call({ method: "GET", path: `/api/runs/${encodeURIComponent(runId)}`, notFound: RUN_NOT_FOUND });
  }

  async waitForRun(
    runId: string,
    opts: { timeoutMs: number; intervalMs?: number; onProgress?: (s: RunStatus) => void },
  ): Promise<RunStatus> {
    const deadline = Date.now() + opts.timeoutMs;
    for (;;) {
      const s = await this.status(runId);
      opts.onProgress?.(s);
      if (FINAL_PHASES.includes(s.phase) || Date.now() >= deadline) return s;
      await this.sleep(opts.intervalMs ?? 5_000);
    }
  }

  recommendations(runId: string): Promise<Recommendations> {
    return this.call({
      method: "GET",
      path: `/api/runs/${encodeURIComponent(runId)}/recommendations`,
      conflict: "The analysis isn't finished yet. Check again with `status --wait`.",
      notFound: RUN_NOT_FOUND,
    });
  }

  feedback(runId: string, recId: string, body: Feedback): Promise<unknown> {
    return this.call({
      method: "POST",
      path: `/api/runs/${encodeURIComponent(runId)}/recommendations/${encodeURIComponent(recId)}/feedback`,
      body,
      conflict: "The analysis isn't finished yet, so there is nothing to rate.",
    });
  }

  setVisibility(runId: string, visibility: "private" | "link"): Promise<{ visibility: string }> {
    return this.call({
      method: "POST",
      path: `/api/runs/${encodeURIComponent(runId)}/visibility`,
      body: { visibility },
      notFound: RUN_NOT_FOUND,
    });
  }

  deleteMyData(): Promise<void> {
    return this.call({ method: "DELETE", path: "/api/me/data" });
  }
}

/** FastAPI's `{"detail": ...}`; anything else (a load-balancer page) is cut to a short excerpt. */
async function errorDetail(res: Response): Promise<string> {
  const text = await res.text();
  if (!res.headers.get("content-type")?.includes("application/json")) return text.slice(0, 200);
  let detail: unknown;
  try {
    ({ detail } = JSON.parse(text) as { detail?: unknown });
  } catch {
    return text.slice(0, 200); // Mislabelled body; show what there is.
  }
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((d: { loc?: unknown[]; msg?: string }) => `${(d.loc ?? []).join(".")}: ${d.msg}`).join("; ");
  }
  return text.slice(0, 200);
}

/**
 * Rate limits (429 with Retry-After) and outages are retried; quota and capacity 429s are not.
 * A call that could create a second record is retried only on 503, which the load balancer
 * returns without reaching the server.
 */
function retryDelayMs(res: Response, attempt: number, idempotent: boolean): number | undefined {
  const after = Number(res.headers.get("retry-after"));
  if (res.status === 429 && Number.isFinite(after) && after > 0) {
    const ms = after * 1000;
    return ms <= MAX_RETRY_WAIT_MS ? ms : undefined;
  }
  if (res.status === 503 || (idempotent && (res.status === 502 || res.status === 504))) return 2_000 * 2 ** attempt;
  return undefined;
}

function explain(res: Response, detail: string, c: Call): string {
  switch (res.status) {
    case 401:
      return `The server didn't accept this machine's token. Try again; if it keeps failing, report it at ${ISSUES_URL}.`;
    case 404:
      return c.notFound ?? sentence(detail || "Not found");
    case 409:
      return c.conflict ?? sentence(detail);
    case 410:
      return `${sentence(detail || "This run ended without a report")} Start a new analysis to get a report.`;
    case 413:
      return `${sentence(detail)} Use a shorter --days, or leave out large sessions with --exclude-session.`;
    case 422:
      if (/window/i.test(detail)) return `${sentence(detail)} Use a shorter --days.`;
      if (/size does not match/i.test(detail)) return `${sentence(detail)} Run the command again.`;
      return `The server rejected the request: ${sentence(detail)} Updating the CLI may fix this.`;
    case 429: {
      const after = Number(res.headers.get("retry-after"));
      if (Number.isFinite(after) && after > 0) return `Too many requests. Wait ${after} seconds and try again.`;
      return sentence(detail || "Too many requests. Wait a minute and try again");
    }
    default:
      return `The server returned HTTP ${res.status}${detail ? `: ${sentence(detail)}` : "."} Try again in a few minutes.`;
  }
}

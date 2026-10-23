#!/usr/bin/env node

// cli/src/main.ts
import { parseArgs as parseArgs2 } from "node:util";

// cli/src/api.ts
import { homedir } from "node:os";
import { isAbsolute, join as join2 } from "node:path";

// cli/src/auth.ts
import { link, mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

// cli/src/net.ts
function unreachable(err, host, env) {
  const e = err;
  if (e.name === "TimeoutError") return `${host} didn't respond in time. Try again in a few minutes.`;
  const why = e.cause?.code ?? e.cause?.message ?? e.message;
  const proxied = (env.HTTPS_PROXY || env.https_proxy) && !env.NODE_USE_ENV_PROXY;
  const hint = proxied ? " You have HTTPS_PROXY set; Node uses it only when NODE_USE_ENV_PROXY=1 is also set." : "";
  return `Couldn't reach ${host} (${why}). Check your connection and try again.${hint}`;
}

// cli/src/auth.ts
var SignInError = class extends Error {
  constructor(message, reason = "failed") {
    super(message);
    this.reason = reason;
    this.name = "SignInError";
  }
  reason;
};
var CREDENTIALS = "credentials.json";
var ACCESS = "access-token.json";
var LOCK = "renew.lock";
var MAX_POLL_INTERVAL_S = 30;
var HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i;
var PENDING = "pending-login.json";
var TIMEOUT_MS = 3e4;
var STALE_LOCK_MS = 3 * TIMEOUT_MS;
var EXPIRY_MARGIN_MS = 6e4;
var REFUSALS = /* @__PURE__ */ new Map([
  ["unapproved_authentication_method", "Your organization requires its own sign-in, which the analyzer doesn't support yet."],
  ["unapproved_audience", "This sign-in can't be used for the analyzer."]
]);
function emailFrom(idToken) {
  const payload = idToken?.split(".")[1];
  if (!payload) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return typeof claims.email === "string" ? claims.email : null;
  } catch {
    return null;
  }
}
var SERVER_ALIASES = { "analyzer.revefi.com": "optimizer.revefi.com" };
function canonicalHost(host) {
  return SERVER_ALIASES[host] ?? host;
}
function sameOrigin(a, b2) {
  try {
    const [x, y] = [new URL(a), new URL(b2)];
    return x.protocol === y.protocol && canonicalHost(x.host) === canonicalHost(y.host);
  } catch {
    return false;
  }
}
function isSignInPage(link2, domain) {
  try {
    const url = new URL(link2);
    return url.protocol === "https:" && url.host === domain && !url.username && !url.password;
  } catch {
    return false;
  }
}
async function writePrivate(file, value) {
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}
`, { mode: 384 });
  await rename(tmp, file);
}
var isMissing = (err) => err.code === "ENOENT";
async function breakStaleLock(lock, staleMtime) {
  const moved = `${lock}.${process.pid}.stale`;
  try {
    await rename(lock, moved);
  } catch (err) {
    if (isMissing(err)) return;
    throw err;
  }
  try {
    if ((await stat(moved)).mtimeMs !== staleMtime) await link(moved, lock);
  } catch (err) {
    if (err.code !== "EEXIST") throw err;
  } finally {
    await rm(moved, { force: true });
  }
}
var Auth = class {
  constructor(opts) {
    this.opts = opts;
    this.base = opts.base.replace(/\/+$/, "");
    this.fetch = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? ((ms2) => new Promise((r) => setTimeout(r, ms2)));
    this.now = opts.now ?? Date.now;
  }
  opts;
  base;
  fetch;
  sleep;
  now;
  access;
  file(name) {
    return join(this.opts.dir, name);
  }
  get login() {
    return this.opts.loginCommand ?? "revefi-agent-analyzer login";
  }
  async readJson(name) {
    const file = this.file(name);
    try {
      return JSON.parse(await readFile(file, "utf8"));
    } catch (err) {
      if (isMissing(err)) return null;
      throw new SignInError(`${file} is damaged. Delete it and run \`${this.login}\` again.`);
    }
  }
  notSignedIn() {
    return new SignInError(`You're not signed in to ${new URL(this.base).host}. Run \`${this.login}\` first.`, "signed_out");
  }
  /** Runs fn while holding this server's renewal lock, so two processes never renew at once. */
  async withLock(fn) {
    const lock = this.file(LOCK);
    for (; ; ) {
      try {
        const handle = await open(lock, "wx", 384);
        await handle.close();
        break;
      } catch (err) {
        if (err.code !== "EEXIST") throw err;
      }
      let mtime = 0;
      try {
        mtime = (await stat(lock)).mtimeMs;
      } catch (err) {
        if (!isMissing(err)) throw err;
        continue;
      }
      if (Date.now() - mtime > STALE_LOCK_MS) await breakStaleLock(lock, mtime);
      else await this.sleep(200);
    }
    try {
      return await fn();
    } finally {
      await rm(lock, { force: true });
    }
  }
  async saveAccess(token, expiresIn) {
    const cached = { token, expires_at: this.now() + (expiresIn ?? 0) * 1e3 };
    this.access = { token, expiresAt: cached.expires_at };
    await writePrivate(this.file(ACCESS), cached);
    return token;
  }
  async cachedAccess(rejected) {
    let cached = null;
    try {
      cached = await this.readJson(ACCESS);
    } catch (err) {
      if (!(err instanceof SignInError)) throw err;
    }
    if (!cached || cached.token === rejected || cached.expires_at - EXPIRY_MARGIN_MS <= this.now()) return null;
    this.access = { token: cached.token, expiresAt: cached.expires_at };
    return cached.token;
  }
  async post(url, form) {
    let res;
    try {
      res = await this.fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams(form).toString(),
        signal: AbortSignal.timeout(TIMEOUT_MS)
      });
    } catch (err) {
      throw new SignInError(unreachable(err, new URL(url).host, this.opts.env ?? process.env));
    }
    const text = await res.text();
    try {
      return { status: res.status, body: text ? JSON.parse(text) : {} };
    } catch {
      return { status: res.status, body: {} };
    }
  }
  async config() {
    let res;
    try {
      res = await this.fetch(`${this.base}/api/auth/config`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (err) {
      throw new SignInError(unreachable(err, new URL(this.base).host, this.opts.env ?? process.env));
    }
    if (res.status === 503) throw new SignInError(`${new URL(this.base).host} doesn't offer sign-in yet.`);
    let body = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    if (!res.ok || !body?.domain || !HOST.test(body.domain) || !body.audience || !body.cli_client_id) {
      throw new SignInError(`${new URL(this.base).host} returned an unexpected sign-in configuration. Try again later.`);
    }
    if (!sameOrigin(body.audience, this.base)) {
      throw new SignInError(`${new URL(this.base).host} asked for a sign-in to a different server. Check --api and REVEFI_ANALYZER_API.`);
    }
    return { domain: body.domain, audience: body.audience, cli_client_id: body.cli_client_id };
  }
  /** Starts a device login and remembers it, so `finishLogin` can run in a later process. */
  async startLogin() {
    const config = await this.config();
    const { status, body } = await this.post(`https://${config.domain}/oauth/device/code`, {
      client_id: config.cli_client_id,
      audience: config.audience,
      scope: "openid email offline_access"
    });
    const code = body;
    if (status !== 200 || !code.device_code || !code.user_code || !code.verification_uri_complete) {
      throw new SignInError(`Couldn't start sign-in (${code.error_description ?? `HTTP ${status}`}). Try again.`);
    }
    if (!isSignInPage(code.verification_uri_complete, config.domain)) {
      throw new SignInError(`${config.domain} returned an unexpected sign-in link. Try again later.`);
    }
    const pending = {
      user_code: code.user_code,
      verification_uri_complete: code.verification_uri_complete,
      expires_at: this.now() + (code.expires_in ?? 900) * 1e3,
      interval: code.interval ?? 5,
      device_code: code.device_code,
      config
    };
    await mkdir(this.opts.dir, { recursive: true, mode: 448 });
    await writePrivate(this.file(PENDING), pending);
    return pending;
  }
  async expired() {
    await rm(this.file(PENDING), { force: true });
    return new SignInError(`The sign-in code expired. Run \`${this.login}\` again.`);
  }
  /** Waits for the user to approve the pending login, then stores the refresh token. */
  async finishLogin(opts = {}) {
    const pending = await this.readJson(PENDING);
    if (!pending) throw new SignInError(`No sign-in is in progress. Run \`${this.login}\` to start one.`);
    const waitUntil = this.now() + (opts.timeoutMs ?? Number.POSITIVE_INFINITY);
    let interval = pending.interval;
    for (; ; ) {
      if (this.now() >= pending.expires_at) throw await this.expired();
      let body = {};
      try {
        ({ body } = await this.post(`https://${pending.config.domain}/oauth/token`, {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: pending.device_code,
          client_id: pending.config.cli_client_id
        }));
      } catch {
        body = {};
      }
      if (body.access_token) {
        if (!body.refresh_token) {
          await rm(this.file(PENDING), { force: true });
          throw new SignInError(`${new URL(this.base).host} isn't set up for command-line sign-in yet. Report it to Revefi.`);
        }
        return { email: await this.signedIn(pending.config, body) };
      }
      if (body.error === "expired_token") throw await this.expired();
      if (body.error === "access_denied" || body.error === "invalid_grant") {
        await rm(this.file(PENDING), { force: true });
        const why = REFUSALS.get(body.error_description ?? "") ?? "Sign-in was refused or cancelled.";
        throw new SignInError(`${why} Run \`${this.login}\` to try again.`);
      }
      if (body.error !== "authorization_pending") interval = Math.min(interval + 5, MAX_POLL_INTERVAL_S);
      const next = this.now() + interval * 1e3;
      if (next >= pending.expires_at) throw await this.expired();
      if (next > waitUntil) {
        throw new SignInError(
          `Still waiting for you to approve the sign-in in your browser. Run \`${this.login} --wait\` once you have.`,
          "pending"
        );
      }
      await this.sleep(interval * 1e3);
    }
  }
  /** Stores a new sign-in, revoking the one it replaces. */
  async signedIn(config, body) {
    const previous = await this.readJson(CREDENTIALS);
    const email = emailFrom(body.id_token);
    await writePrivate(this.file(CREDENTIALS), {
      domain: config.domain,
      audience: config.audience,
      client_id: config.cli_client_id,
      refresh_token: body.refresh_token ?? "",
      email
    });
    await rm(this.file(PENDING), { force: true });
    await this.saveAccess(body.access_token ?? "", body.expires_in);
    if (previous && previous.refresh_token !== body.refresh_token) await this.revoke(previous);
    return email;
  }
  async email() {
    const creds = await this.readJson(CREDENTIALS);
    if (!creds) throw this.notSignedIn();
    return creds.email;
  }
  /** A valid access token, renewed when needed; `force` means the current one was just rejected. */
  async accessToken(force = false) {
    const rejected = force ? this.access?.token : void 0;
    if (!force && this.access && this.access.expiresAt - EXPIRY_MARGIN_MS > this.now()) return this.access.token;
    const fromDisk = await this.cachedAccess(rejected);
    if (fromDisk) return fromDisk;
    if (!await this.readJson(CREDENTIALS)) throw this.notSignedIn();
    await mkdir(this.opts.dir, { recursive: true, mode: 448 });
    return this.withLock(async () => {
      const renewed = await this.cachedAccess(rejected);
      if (renewed) return renewed;
      const creds = await this.readJson(CREDENTIALS);
      if (!creds) throw this.notSignedIn();
      const { status, body } = await this.post(`https://${creds.domain}/oauth/token`, {
        grant_type: "refresh_token",
        client_id: creds.client_id,
        refresh_token: creds.refresh_token
      });
      if (body.access_token) {
        if (body.refresh_token) await writePrivate(this.file(CREDENTIALS), { ...creds, refresh_token: body.refresh_token });
        return this.saveAccess(body.access_token, body.expires_in);
      }
      if (body.error === "invalid_grant") {
        await rm(this.file(CREDENTIALS), { force: true });
        await rm(this.file(ACCESS), { force: true });
        throw new SignInError(`Your sign-in to ${new URL(this.base).host} has expired. Run \`${this.login}\` again.`, "signed_out");
      }
      if (status === 429) throw new SignInError("Sign-in is busy. Wait a minute and try again.");
      throw new SignInError(`Couldn't renew your sign-in (HTTP ${status}). Try again in a few minutes.`);
    });
  }
  async revoke(creds) {
    try {
      const { status } = await this.post(`https://${creds.domain}/oauth/revoke`, {
        client_id: creds.client_id,
        token: creds.refresh_token
      });
      return status === 200;
    } catch {
      return false;
    }
  }
  /** Forgets the sign-in, revoking its refresh token at Auth0 when it can be reached. */
  async logout() {
    const creds = await this.readJson(CREDENTIALS);
    await rm(this.file(PENDING), { force: true });
    await rm(this.file(ACCESS), { force: true });
    this.access = void 0;
    if (!creds) return { signedIn: false, revoked: false };
    const revoked = await this.revoke(creds);
    await rm(this.file(CREDENTIALS), { force: true });
    return { signedIn: true, revoked };
  }
};

// cli/src/api.ts
var DEFAULT_API = "https://optimizer.revefi.com";
var ISSUES_URL = "https://github.com/revefi/agent-analyzer/issues";
var FINAL_PHASES = ["done", "failed", "deferred"];
var ApiError = class extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
  status;
};
function configDir(env = process.env) {
  const xdg = env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : void 0;
  const base = xdg || process.platform === "win32" && env.APPDATA || join2(homedir(), ".config");
  return join2(base, "revefi", "agent-analyzer");
}
var MAX_RETRY_WAIT_MS = 6e4;
var CALL_TIMEOUT_MS = 3e4;
var RUN_NOT_FOUND = "Run not found. Only the account that uploaded a run can manage it, and deleted runs are gone.";
var sentence = (s3) => /[.!?]$/.test(s3.trim()) ? s3.trim() : `${s3.trim()}.`;
var Client = class {
  constructor(opts) {
    this.opts = opts;
    this.base = opts.base.replace(/\/+$/, "");
    this.fetch = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? ((ms2) => new Promise((r) => setTimeout(r, ms2)));
    this.env = opts.env ?? process.env;
  }
  opts;
  fetch;
  sleep;
  env;
  base;
  /** Absolute URL for a server-relative link such as a run's `report_url`. */
  link(path) {
    return new URL(path, `${this.base}/`).toString();
  }
  /** Never echoes the URL or the raw error: an upload URL carries a signature. */
  async send(url, init, host) {
    try {
      return await this.fetch(url, init);
    } catch (err) {
      throw new ApiError(unreachable(err, host, this.env));
    }
  }
  /** `force` renews the token, only on the call straight after a 401; retries reuse the renewed one. */
  async call(c, attempt = 0, refreshed = false, force = false) {
    const headers = { "user-agent": this.opts.userAgent, accept: "application/json" };
    if (c.body !== void 0) headers["content-type"] = "application/json";
    headers.authorization = `Bearer ${await this.opts.token(force)}`;
    const res = await this.send(
      `${this.base}${c.path}`,
      {
        method: c.method,
        headers,
        body: c.body === void 0 ? void 0 : JSON.stringify(c.body),
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS)
      },
      new URL(this.base).host
    );
    if (res.ok) return res.status === 204 ? void 0 : await res.json();
    const detail = await errorDetail(res);
    const wait = retryDelayMs(res, attempt, c.idempotent !== false);
    if (wait !== void 0 && attempt < 2) {
      await this.sleep(wait);
      return this.call(c, attempt + 1, refreshed);
    }
    if (res.status === 401) {
      if (!refreshed) return this.call(c, attempt, true, true);
      const login = this.opts.loginCommand ?? "revefi-agent-analyzer login";
      throw new SignInError(`Your sign-in wasn't accepted. Run \`${login}\` again.`, "signed_out");
    }
    throw new ApiError(explain(res, detail, c), res.status);
  }
  createRun(manifest) {
    return this.call({ method: "POST", path: "/api/runs", body: manifest, idempotent: false });
  }
  /** PUTs the archive to the presigned URL; the signed headers must be sent exactly as given. */
  async upload(target, body) {
    const declared = Object.entries(target.headers).find(([k2]) => k2.toLowerCase() === "content-length")?.[1];
    if (declared !== void 0 && Number(declared) !== body.size) {
      throw new ApiError("The archive changed after it was packed. Run the command again.");
    }
    const timeout = Math.max(12e4, body.size / 5e4 * 1e3);
    const res = await this.send(
      target.url,
      { method: target.method ?? "PUT", headers: target.headers, body, signal: AbortSignal.timeout(timeout) },
      "storage"
    );
    if (res.ok) return;
    const code = (await res.text()).match(/<Code>([A-Za-z]{1,64})<\/Code>/)?.[1];
    const expired = res.status === 403 && Date.parse(target.expires_at) < Date.now();
    const next = expired ? "The upload link expired. Run the command again." : res.status === 403 ? `Update the CLI, and if that doesn't help, report it at ${ISSUES_URL}.` : "Run the command again.";
    throw new ApiError(`Storage rejected the upload (HTTP ${res.status}${code ? `, ${code}` : ""}). ${next}`, res.status);
  }
  complete(runId) {
    return this.call({
      method: "POST",
      path: `/api/runs/${encodeURIComponent(runId)}/complete`,
      conflict: "The server didn't receive the upload. Run the command again.",
      notFound: RUN_NOT_FOUND
    });
  }
  status(runId) {
    return this.call({ method: "GET", path: `/api/runs/${encodeURIComponent(runId)}`, notFound: RUN_NOT_FOUND });
  }
  async waitForRun(runId, opts) {
    const deadline = Date.now() + opts.timeoutMs;
    for (; ; ) {
      const s3 = await this.status(runId);
      opts.onProgress?.(s3);
      if (FINAL_PHASES.includes(s3.phase) || Date.now() >= deadline) return s3;
      await this.sleep(opts.intervalMs ?? 5e3);
    }
  }
  recommendations(runId) {
    return this.call({
      method: "GET",
      path: `/api/runs/${encodeURIComponent(runId)}/recommendations`,
      conflict: "The analysis isn't finished yet. Check again with `status --wait`.",
      notFound: RUN_NOT_FOUND
    });
  }
  feedback(runId, recId, body) {
    return this.call({
      method: "POST",
      path: `/api/runs/${encodeURIComponent(runId)}/recommendations/${encodeURIComponent(recId)}/feedback`,
      body,
      conflict: "The analysis isn't finished yet, so there is nothing to rate."
    });
  }
  sharing(runId) {
    return this.call({ method: "GET", path: `/api/runs/${encodeURIComponent(runId)}/sharing`, notFound: RUN_NOT_FOUND });
  }
  setSharing(runId, sharing) {
    return this.call({
      method: "PUT",
      path: `/api/runs/${encodeURIComponent(runId)}/sharing`,
      body: sharing,
      notFound: RUN_NOT_FOUND
    });
  }
  deleteMyData() {
    return this.call({ method: "DELETE", path: "/api/me/data" });
  }
};
async function errorDetail(res) {
  const text = await res.text();
  if (!res.headers.get("content-type")?.includes("application/json")) return text.slice(0, 200);
  let detail;
  try {
    ({ detail } = JSON.parse(text));
  } catch {
    return text.slice(0, 200);
  }
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => `${(d.loc ?? []).join(".")}: ${d.msg}`).join("; ");
  }
  return text.slice(0, 200);
}
function retryDelayMs(res, attempt, idempotent) {
  const after = Number(res.headers.get("retry-after"));
  if (res.status === 429 && Number.isFinite(after) && after > 0) {
    const ms2 = after * 1e3;
    return ms2 <= MAX_RETRY_WAIT_MS ? ms2 : void 0;
  }
  if (res.status === 503 || idempotent && (res.status === 502 || res.status === 504)) return 2e3 * 2 ** attempt;
  return void 0;
}
function explain(res, detail, c) {
  switch (res.status) {
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

// cli/src/commands.ts
import { execFileSync, spawn } from "node:child_process";
import { existsSync, openAsBlob } from "node:fs";
import { readFile as readFile4, rm as rm3, writeFile as writeFile4 } from "node:fs/promises";
import { homedir as homedir3 } from "node:os";
import { basename, dirname as dirname2, join as join7, relative as relative2, resolve } from "node:path";
import { createInterface as createInterface3 } from "node:readline/promises";
import { parseArgs } from "node:util";

// cli/src/collect.ts
import { createReadStream } from "node:fs";
import { readdir, stat as stat2 } from "node:fs/promises";
import { homedir as homedir2 } from "node:os";
import { join as join3, relative, sep } from "node:path";
import { createInterface } from "node:readline";
function defaultProjectsDir(env = process.env) {
  return join3(env.CLAUDE_CONFIG_DIR ?? join3(homedir2(), ".claude"), "projects");
}
function encodeProjectDir(cwd) {
  return cwd.replace(/[^A-Za-z0-9]/g, "-");
}
function utcToday(now = /* @__PURE__ */ new Date()) {
  return now.toISOString().slice(0, 10);
}
function windowEndingOn(today, days) {
  if (!Number.isInteger(days) || days < 1) throw new RangeError(`days must be a whole number of at least 1, got ${days}`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(today)) throw new RangeError(`today must be YYYY-MM-DD, got ${today}`);
  const start = /* @__PURE__ */ new Date(`${today}T00:00:00Z`);
  start.setUTCDate(start.getUTCDate() - (days - 1));
  return { days, start: start.toISOString().slice(0, 10), end: today };
}
var foldCase = process.platform === "win32" ? (s3) => s3.toLowerCase() : (s3) => s3;
async function readHead(file, needCwd, window) {
  const input = createReadStream(file, "utf8");
  const lines = createInterface({ input, crlfDelay: Infinity });
  const head = {};
  try {
    for await (const line of lines) {
      if (!line.trim()) continue;
      let rec;
      try {
        rec = JSON.parse(line);
      } catch {
        continue;
      }
      if (typeof rec !== "object" || rec === null) continue;
      const r = rec;
      if (!head.day && typeof r.timestamp === "string" && r.timestamp) head.day = r.timestamp.slice(0, 10);
      if (!head.cwd && typeof r.cwd === "string") head.cwd = r.cwd;
      if (head.day && (head.day < window.start || head.day > window.end)) break;
      if (head.day && (head.cwd || !needCwd)) break;
    }
  } finally {
    lines.close();
    input.destroy();
  }
  return head;
}
var SUBAGENT_FILE = /^agent-.+\.(?:jsonl|meta\.json)$/;
async function subagentFiles(sessionDir) {
  const dir = join3(sessionDir, "subagents");
  const entries = await readdir(dir, { withFileTypes: true }).catch(ignoreMissing);
  return entries.filter((e) => e.isFile() && SUBAGENT_FILE.test(e.name)).map((e) => join3(dir, e.name)).sort();
}
function ignoreMissing(err) {
  if (err.code === "ENOENT" || err.code === "ENOTDIR") return [];
  throw err;
}
function isVanished(err) {
  const code = err.code;
  return code === "ENOENT" || code === "EISDIR";
}
function inRoot(cwd, root, project) {
  if (cwd === void 0) return foldCase(project) === foldCase(encodeProjectDir(root));
  const [c, r] = [foldCase(cwd), foldCase(root)];
  return c === r || c.startsWith(r.endsWith(sep) ? r : r + sep);
}
async function readSession(projectsDir, project, id, opts, window) {
  const transcript = join3(projectsDir, project, `${id}.jsonl`);
  const info = await stat2(transcript);
  if (info.mtime.toISOString().slice(0, 10) < window.start) return void 0;
  const head = await readHead(transcript, opts.root !== void 0, window);
  if (!head.day || head.day < window.start || head.day > window.end) return void 0;
  if (opts.root !== void 0 && !inRoot(head.cwd, opts.root, project)) return void 0;
  const subs = await subagentFiles(join3(projectsDir, project, id));
  const sizes = await Promise.all(subs.map(async (f2) => (await stat2(f2)).size));
  return {
    project,
    id,
    day: head.day,
    files: [transcript, ...subs],
    bytes: sizes.reduce((a, b2) => a + b2, info.size)
  };
}
async function collect(opts) {
  const window = windowEndingOn(opts.today, opts.days);
  const exclude = (opts.exclude ?? []).filter((x) => x.length > 0);
  const prefix = opts.root === void 0 ? "" : foldCase(encodeProjectDir(opts.root).slice(0, 200));
  const projects = (await readdir(opts.projectsDir, { withFileTypes: true }).catch(ignoreMissing)).filter((e) => e.isDirectory() && foldCase(e.name).startsWith(prefix)).map((e) => e.name).sort();
  const sessions = [];
  for (const project of projects) {
    const entries = await readdir(join3(opts.projectsDir, project), { withFileTypes: true }).catch(ignoreMissing);
    const ids = entries.filter((e) => e.isFile() && e.name.endsWith(".jsonl")).map((e) => e.name.slice(0, -".jsonl".length)).filter((id) => !exclude.some((x) => id.startsWith(x))).sort();
    for (const id of ids) {
      try {
        const s3 = await readSession(opts.projectsDir, project, id, opts, window);
        if (s3) sessions.push(s3);
      } catch (err) {
        if (!isVanished(err)) throw err;
      }
    }
  }
  return { window, sessions };
}
function archivePath(projectsDir, file) {
  return ["projects", ...relative(projectsDir, file).split(sep)].join("/");
}

// cli/src/pack.ts
import { realpath, stat as stat3 } from "node:fs/promises";
import { join as join5, sep as sep2 } from "node:path";

// node_modules/.pnpm/tar@7.5.22/node_modules/tar/dist/esm/index.min.js
import Qr from "events";
import I from "fs";
import { EventEmitter as Di } from "node:events";
import Cs from "node:stream";
import { StringDecoder as Hr } from "node:string_decoder";
import cr from "node:path";
import Kt from "node:fs";
import { dirname as Fn, parse as kn } from "path";
import { EventEmitter as Dn } from "events";
import zi from "assert";
import { Buffer as Ot } from "buffer";
import * as Ps from "zlib";
import en from "zlib";
import { posix as Zt } from "node:path";
import { basename as _n } from "node:path";
import mi from "fs";
import X from "fs";
import js from "path";
import { win32 as Pn } from "node:path";
import ar from "path";
import Br from "node:fs";
import co from "node:assert";
import { randomBytes as Mr } from "node:crypto";
import u from "node:fs";
import R from "node:path";
import pr from "fs";
import wi from "node:fs";
import we from "node:path";
import k from "node:fs";
import ro from "node:fs/promises";
import Si from "node:path";
import { join as xr } from "node:path";
import v from "node:fs";
import Pr from "node:path";
var zr = Object.defineProperty;
var Ur = (s3, t) => {
  for (var e in t) zr(s3, e, { get: t[e], enumerable: true });
};
var Ds = typeof process == "object" && process ? process : { stdout: null, stderr: null };
var Wr = (s3) => !!s3 && typeof s3 == "object" && (s3 instanceof A || s3 instanceof Cs || Gr(s3) || Zr(s3));
var Gr = (s3) => !!s3 && typeof s3 == "object" && s3 instanceof Di && typeof s3.pipe == "function" && s3.pipe !== Cs.Writable.prototype.pipe;
var Zr = (s3) => !!s3 && typeof s3 == "object" && s3 instanceof Di && typeof s3.write == "function" && typeof s3.end == "function";
var Q = /* @__PURE__ */ Symbol("EOF");
var J = /* @__PURE__ */ Symbol("maybeEmitEnd");
var nt = /* @__PURE__ */ Symbol("emittedEnd");
var De = /* @__PURE__ */ Symbol("emittingEnd");
var qt = /* @__PURE__ */ Symbol("emittedError");
var Ne = /* @__PURE__ */ Symbol("closed");
var Ns = /* @__PURE__ */ Symbol("read");
var Ae = /* @__PURE__ */ Symbol("flush");
var As = /* @__PURE__ */ Symbol("flushChunk");
var z = /* @__PURE__ */ Symbol("encoding");
var Mt = /* @__PURE__ */ Symbol("decoder");
var g = /* @__PURE__ */ Symbol("flowing");
var Qt = /* @__PURE__ */ Symbol("paused");
var Bt = /* @__PURE__ */ Symbol("resume");
var b = /* @__PURE__ */ Symbol("buffer");
var N = /* @__PURE__ */ Symbol("pipes");
var _ = /* @__PURE__ */ Symbol("bufferLength");
var bi = /* @__PURE__ */ Symbol("bufferPush");
var Ie = /* @__PURE__ */ Symbol("bufferShift");
var L = /* @__PURE__ */ Symbol("objectMode");
var S = /* @__PURE__ */ Symbol("destroyed");
var _i = /* @__PURE__ */ Symbol("error");
var Oi = /* @__PURE__ */ Symbol("emitData");
var Is = /* @__PURE__ */ Symbol("emitEnd");
var Ti = /* @__PURE__ */ Symbol("emitEnd2");
var Z = /* @__PURE__ */ Symbol("async");
var xi = /* @__PURE__ */ Symbol("abort");
var Ce = /* @__PURE__ */ Symbol("aborted");
var Jt = /* @__PURE__ */ Symbol("signal");
var Rt = /* @__PURE__ */ Symbol("dataListeners");
var C = /* @__PURE__ */ Symbol("discarded");
var jt = (s3) => Promise.resolve().then(s3);
var Yr = (s3) => s3();
var Kr = (s3) => s3 === "end" || s3 === "finish" || s3 === "prefinish";
var Vr = (s3) => s3 instanceof ArrayBuffer || !!s3 && typeof s3 == "object" && s3.constructor && s3.constructor.name === "ArrayBuffer" && s3.byteLength >= 0;
var $r = (s3) => !Buffer.isBuffer(s3) && ArrayBuffer.isView(s3);
var Fe = class {
  src;
  dest;
  opts;
  ondrain;
  constructor(t, e, i) {
    this.src = t, this.dest = e, this.opts = i, this.ondrain = () => t[Bt](), this.dest.on("drain", this.ondrain);
  }
  unpipe() {
    this.dest.removeListener("drain", this.ondrain);
  }
  proxyErrors(t) {
  }
  end() {
    this.unpipe(), this.opts.end && this.dest.end();
  }
};
var Li = class extends Fe {
  unpipe() {
    this.src.removeListener("error", this.proxyErrors), super.unpipe();
  }
  constructor(t, e, i) {
    super(t, e, i), this.proxyErrors = (r) => this.dest.emit("error", r), t.on("error", this.proxyErrors);
  }
};
var Xr = (s3) => !!s3.objectMode;
var qr = (s3) => !s3.objectMode && !!s3.encoding && s3.encoding !== "buffer";
var A = class extends Di {
  [g] = false;
  [Qt] = false;
  [N] = [];
  [b] = [];
  [L];
  [z];
  [Z];
  [Mt];
  [Q] = false;
  [nt] = false;
  [De] = false;
  [Ne] = false;
  [qt] = null;
  [_] = 0;
  [S] = false;
  [Jt];
  [Ce] = false;
  [Rt] = 0;
  [C] = false;
  writable = true;
  readable = true;
  constructor(...t) {
    let e = t[0] || {};
    if (super(), e.objectMode && typeof e.encoding == "string") throw new TypeError("Encoding and objectMode may not be used together");
    Xr(e) ? (this[L] = true, this[z] = null) : qr(e) ? (this[z] = e.encoding, this[L] = false) : (this[L] = false, this[z] = null), this[Z] = !!e.async, this[Mt] = this[z] ? new Hr(this[z]) : null, e && e.debugExposeBuffer === true && Object.defineProperty(this, "buffer", { get: () => this[b] }), e && e.debugExposePipes === true && Object.defineProperty(this, "pipes", { get: () => this[N] });
    let { signal: i } = e;
    i && (this[Jt] = i, i.aborted ? this[xi]() : i.addEventListener("abort", () => this[xi]()));
  }
  get bufferLength() {
    return this[_];
  }
  get encoding() {
    return this[z];
  }
  set encoding(t) {
    throw new Error("Encoding must be set at instantiation time");
  }
  setEncoding(t) {
    throw new Error("Encoding must be set at instantiation time");
  }
  get objectMode() {
    return this[L];
  }
  set objectMode(t) {
    throw new Error("objectMode must be set at instantiation time");
  }
  get async() {
    return this[Z];
  }
  set async(t) {
    this[Z] = this[Z] || !!t;
  }
  [xi]() {
    this[Ce] = true, this.emit("abort", this[Jt]?.reason), this.destroy(this[Jt]?.reason);
  }
  get aborted() {
    return this[Ce];
  }
  set aborted(t) {
  }
  write(t, e, i) {
    if (this[Ce]) return false;
    if (this[Q]) throw new Error("write after end");
    if (this[S]) return this.emit("error", Object.assign(new Error("Cannot call write after a stream was destroyed"), { code: "ERR_STREAM_DESTROYED" })), true;
    typeof e == "function" && (i = e, e = "utf8"), e || (e = "utf8");
    let r = this[Z] ? jt : Yr;
    if (!this[L] && !Buffer.isBuffer(t)) {
      if ($r(t)) t = Buffer.from(t.buffer, t.byteOffset, t.byteLength);
      else if (Vr(t)) t = Buffer.from(t);
      else if (typeof t != "string") throw new Error("Non-contiguous data written to non-objectMode stream");
    }
    return this[L] ? (this[g] && this[_] !== 0 && this[Ae](true), this[g] ? this.emit("data", t) : this[bi](t), this[_] !== 0 && this.emit("readable"), i && r(i), this[g]) : t.length ? (typeof t == "string" && !(e === this[z] && !this[Mt]?.lastNeed) && (t = Buffer.from(t, e)), Buffer.isBuffer(t) && this[z] && (t = this[Mt].write(t)), this[g] && this[_] !== 0 && this[Ae](true), this[g] ? this.emit("data", t) : this[bi](t), this[_] !== 0 && this.emit("readable"), i && r(i), this[g]) : (this[_] !== 0 && this.emit("readable"), i && r(i), this[g]);
  }
  read(t) {
    if (this[S]) return null;
    if (this[C] = false, this[_] === 0 || t === 0 || t && t > this[_]) return this[J](), null;
    this[L] && (t = null), this[b].length > 1 && !this[L] && (this[b] = [this[z] ? this[b].join("") : Buffer.concat(this[b], this[_])]);
    let e = this[Ns](t || null, this[b][0]);
    return this[J](), e;
  }
  [Ns](t, e) {
    if (this[L]) this[Ie]();
    else {
      let i = e;
      t === i.length || t === null ? this[Ie]() : typeof i == "string" ? (this[b][0] = i.slice(t), e = i.slice(0, t), this[_] -= t) : (this[b][0] = i.subarray(t), e = i.subarray(0, t), this[_] -= t);
    }
    return this.emit("data", e), !this[b].length && !this[Q] && this.emit("drain"), e;
  }
  end(t, e, i) {
    return typeof t == "function" && (i = t, t = void 0), typeof e == "function" && (i = e, e = "utf8"), t !== void 0 && this.write(t, e), i && this.once("end", i), this[Q] = true, this.writable = false, (this[g] || !this[Qt]) && this[J](), this;
  }
  [Bt]() {
    this[S] || (!this[Rt] && !this[N].length && (this[C] = true), this[Qt] = false, this[g] = true, this.emit("resume"), this[b].length ? this[Ae]() : this[Q] ? this[J]() : this.emit("drain"));
  }
  resume() {
    return this[Bt]();
  }
  pause() {
    this[g] = false, this[Qt] = true, this[C] = false;
  }
  get destroyed() {
    return this[S];
  }
  get flowing() {
    return this[g];
  }
  get paused() {
    return this[Qt];
  }
  [bi](t) {
    this[L] ? this[_] += 1 : this[_] += t.length, this[b].push(t);
  }
  [Ie]() {
    return this[L] ? this[_] -= 1 : this[_] -= this[b][0].length, this[b].shift();
  }
  [Ae](t = false) {
    do
      ;
    while (this[As](this[Ie]()) && this[b].length);
    !t && !this[b].length && !this[Q] && this.emit("drain");
  }
  [As](t) {
    return this.emit("data", t), this[g];
  }
  pipe(t, e) {
    if (this[S]) return t;
    this[C] = false;
    let i = this[nt];
    return e = e || {}, t === Ds.stdout || t === Ds.stderr ? e.end = false : e.end = e.end !== false, e.proxyErrors = !!e.proxyErrors, i ? e.end && t.end() : (this[N].push(e.proxyErrors ? new Li(this, t, e) : new Fe(this, t, e)), this[Z] ? jt(() => this[Bt]()) : this[Bt]()), t;
  }
  unpipe(t) {
    let e = this[N].find((i) => i.dest === t);
    e && (this[N].length === 1 ? (this[g] && this[Rt] === 0 && (this[g] = false), this[N] = []) : this[N].splice(this[N].indexOf(e), 1), e.unpipe());
  }
  addListener(t, e) {
    return this.on(t, e);
  }
  on(t, e) {
    let i = super.on(t, e);
    if (t === "data") this[C] = false, this[Rt]++, !this[N].length && !this[g] && this[Bt]();
    else if (t === "readable" && this[_] !== 0) super.emit("readable");
    else if (Kr(t) && this[nt]) super.emit(t), this.removeAllListeners(t);
    else if (t === "error" && this[qt]) {
      let r = e;
      this[Z] ? jt(() => r.call(this, this[qt])) : r.call(this, this[qt]);
    }
    return i;
  }
  removeListener(t, e) {
    return this.off(t, e);
  }
  off(t, e) {
    let i = super.off(t, e);
    return t === "data" && (this[Rt] = this.listeners("data").length, this[Rt] === 0 && !this[C] && !this[N].length && (this[g] = false)), i;
  }
  removeAllListeners(t) {
    let e = super.removeAllListeners(t);
    return (t === "data" || t === void 0) && (this[Rt] = 0, !this[C] && !this[N].length && (this[g] = false)), e;
  }
  get emittedEnd() {
    return this[nt];
  }
  [J]() {
    !this[De] && !this[nt] && !this[S] && this[b].length === 0 && this[Q] && (this[De] = true, this.emit("end"), this.emit("prefinish"), this.emit("finish"), this[Ne] && this.emit("close"), this[De] = false);
  }
  emit(t, ...e) {
    let i = e[0];
    if (t !== "error" && t !== "close" && t !== S && this[S]) return false;
    if (t === "data") return !this[L] && !i ? false : this[Z] ? (jt(() => this[Oi](i)), true) : this[Oi](i);
    if (t === "end") return this[Is]();
    if (t === "close") {
      if (this[Ne] = true, !this[nt] && !this[S]) return false;
      let n = super.emit("close");
      return this.removeAllListeners("close"), n;
    } else if (t === "error") {
      this[qt] = i, super.emit(_i, i);
      let n = !this[Jt] || this.listeners("error").length ? super.emit("error", i) : false;
      return this[J](), n;
    } else if (t === "resume") {
      let n = super.emit("resume");
      return this[J](), n;
    } else if (t === "finish" || t === "prefinish") {
      let n = super.emit(t);
      return this.removeAllListeners(t), n;
    }
    let r = super.emit(t, ...e);
    return this[J](), r;
  }
  [Oi](t) {
    for (let i of this[N]) i.dest.write(t) === false && this.pause();
    let e = this[C] ? false : super.emit("data", t);
    return this[J](), e;
  }
  [Is]() {
    return this[nt] ? false : (this[nt] = true, this.readable = false, this[Z] ? (jt(() => this[Ti]()), true) : this[Ti]());
  }
  [Ti]() {
    if (this[Mt]) {
      let e = this[Mt].end();
      if (e) {
        for (let i of this[N]) i.dest.write(e);
        this[C] || super.emit("data", e);
      }
    }
    for (let e of this[N]) e.end();
    let t = super.emit("end");
    return this.removeAllListeners("end"), t;
  }
  async collect() {
    let t = Object.assign([], { dataLength: 0 });
    this[L] || (t.dataLength = 0);
    let e = this.promise();
    return this.on("data", (i) => {
      t.push(i), this[L] || (t.dataLength += i.length);
    }), await e, t;
  }
  async concat() {
    if (this[L]) throw new Error("cannot concat in objectMode");
    let t = await this.collect();
    return this[z] ? t.join("") : Buffer.concat(t, t.dataLength);
  }
  async promise() {
    return new Promise((t, e) => {
      this.on(S, () => e(new Error("stream destroyed"))), this.on("error", (i) => e(i)), this.on("end", () => t());
    });
  }
  [Symbol.asyncIterator]() {
    this[C] = false;
    let t = false, e = async () => (this.pause(), t = true, { value: void 0, done: true });
    return { next: () => {
      if (t) return e();
      let r = this.read();
      if (r !== null) return Promise.resolve({ done: false, value: r });
      if (this[Q]) return e();
      let n, o, h = (d) => {
        this.off("data", a), this.off("end", l), this.off(S, c), e(), o(d);
      }, a = (d) => {
        this.off("error", h), this.off("end", l), this.off(S, c), this.pause(), n({ value: d, done: !!this[Q] });
      }, l = () => {
        this.off("error", h), this.off("data", a), this.off(S, c), e(), n({ done: true, value: void 0 });
      }, c = () => h(new Error("stream destroyed"));
      return new Promise((d, y) => {
        o = y, n = d, this.once(S, c), this.once("error", h), this.once("end", l), this.once("data", a);
      });
    }, throw: e, return: e, [Symbol.asyncIterator]() {
      return this;
    }, [Symbol.asyncDispose]: async () => {
    } };
  }
  [Symbol.iterator]() {
    this[C] = false;
    let t = false, e = () => (this.pause(), this.off(_i, e), this.off(S, e), this.off("end", e), t = true, { done: true, value: void 0 }), i = () => {
      if (t) return e();
      let r = this.read();
      return r === null ? e() : { done: false, value: r };
    };
    return this.once("end", e), this.once(_i, e), this.once(S, e), { next: i, throw: e, return: e, [Symbol.iterator]() {
      return this;
    }, [Symbol.dispose]: () => {
    } };
  }
  destroy(t) {
    if (this[S]) return t ? this.emit("error", t) : this.emit(S), this;
    this[S] = true, this[C] = true, this[b].length = 0, this[_] = 0;
    let e = this;
    return typeof e.close == "function" && !this[Ne] && e.close(), t ? this.emit("error", t) : this.emit(S), this;
  }
  static get isStream() {
    return Wr;
  }
};
var Jr = I.writev;
var ht = /* @__PURE__ */ Symbol("_autoClose");
var H = /* @__PURE__ */ Symbol("_close");
var te = /* @__PURE__ */ Symbol("_ended");
var m = /* @__PURE__ */ Symbol("_fd");
var Ni = /* @__PURE__ */ Symbol("_finished");
var tt = /* @__PURE__ */ Symbol("_flags");
var Ai = /* @__PURE__ */ Symbol("_flush");
var ki = /* @__PURE__ */ Symbol("_handleChunk");
var vi = /* @__PURE__ */ Symbol("_makeBuf");
var ie = /* @__PURE__ */ Symbol("_mode");
var ke = /* @__PURE__ */ Symbol("_needDrain");
var Ut = /* @__PURE__ */ Symbol("_onerror");
var Ht = /* @__PURE__ */ Symbol("_onopen");
var Ii = /* @__PURE__ */ Symbol("_onread");
var Pt = /* @__PURE__ */ Symbol("_onwrite");
var at = /* @__PURE__ */ Symbol("_open");
var U = /* @__PURE__ */ Symbol("_path");
var ot = /* @__PURE__ */ Symbol("_pos");
var Y = /* @__PURE__ */ Symbol("_queue");
var zt = /* @__PURE__ */ Symbol("_read");
var Ci = /* @__PURE__ */ Symbol("_readSize");
var j = /* @__PURE__ */ Symbol("_reading");
var ee = /* @__PURE__ */ Symbol("_remain");
var Fi = /* @__PURE__ */ Symbol("_size");
var ve = /* @__PURE__ */ Symbol("_write");
var gt = /* @__PURE__ */ Symbol("_writing");
var Me = /* @__PURE__ */ Symbol("_defaultFlag");
var bt = /* @__PURE__ */ Symbol("_errored");
var _t = class extends A {
  [bt] = false;
  [m];
  [U];
  [Ci];
  [j] = false;
  [Fi];
  [ee];
  [ht];
  constructor(t, e) {
    if (e = e || {}, super(e), this.readable = true, this.writable = false, typeof t != "string") throw new TypeError("path must be a string");
    this[bt] = false, this[m] = typeof e.fd == "number" ? e.fd : void 0, this[U] = t, this[Ci] = e.readSize || 16 * 1024 * 1024, this[j] = false, this[Fi] = typeof e.size == "number" ? e.size : 1 / 0, this[ee] = this[Fi], this[ht] = typeof e.autoClose == "boolean" ? e.autoClose : true, typeof this[m] == "number" ? this[zt]() : this[at]();
  }
  get fd() {
    return this[m];
  }
  get path() {
    return this[U];
  }
  write() {
    throw new TypeError("this is a readable stream");
  }
  end() {
    throw new TypeError("this is a readable stream");
  }
  [at]() {
    I.open(this[U], "r", (t, e) => this[Ht](t, e));
  }
  [Ht](t, e) {
    t ? this[Ut](t) : (this[m] = e, this.emit("open", e), this[zt]());
  }
  [vi]() {
    return Buffer.allocUnsafe(Math.min(this[Ci], this[ee]));
  }
  [zt]() {
    if (!this[j]) {
      this[j] = true;
      let t = this[vi]();
      if (t.length === 0) return process.nextTick(() => this[Ii](null, 0, t));
      I.read(this[m], t, 0, t.length, null, (e, i, r) => this[Ii](e, i, r));
    }
  }
  [Ii](t, e, i) {
    this[j] = false, t ? this[Ut](t) : this[ki](e, i) && this[zt]();
  }
  [H]() {
    if (this[ht] && typeof this[m] == "number") {
      let t = this[m];
      this[m] = void 0, I.close(t, (e) => e ? this.emit("error", e) : this.emit("close"));
    }
  }
  [Ut](t) {
    this[j] = true, this[H](), this.emit("error", t);
  }
  [ki](t, e) {
    let i = false;
    return this[ee] -= t, t > 0 && (i = super.write(t < e.length ? e.subarray(0, t) : e)), (t === 0 || this[ee] <= 0) && (i = false, this[H](), super.end()), i;
  }
  emit(t, ...e) {
    switch (t) {
      case "prefinish":
      case "finish":
        return false;
      case "drain":
        return typeof this[m] == "number" && this[zt](), false;
      case "error":
        return this[bt] ? false : (this[bt] = true, super.emit(t, ...e));
      default:
        return super.emit(t, ...e);
    }
  }
};
var Be = class extends _t {
  [at]() {
    let t = true;
    try {
      this[Ht](null, I.openSync(this[U], "r")), t = false;
    } finally {
      t && this[H]();
    }
  }
  [zt]() {
    let t = true;
    try {
      if (!this[j]) {
        this[j] = true;
        do {
          let e = this[vi](), i = e.length === 0 ? 0 : I.readSync(this[m], e, 0, e.length, null);
          if (!this[ki](i, e)) break;
        } while (true);
        this[j] = false;
      }
      t = false;
    } finally {
      t && this[H]();
    }
  }
  [H]() {
    if (this[ht] && typeof this[m] == "number") {
      let t = this[m];
      this[m] = void 0, I.closeSync(t), this.emit("close");
    }
  }
};
var et = class extends Qr {
  readable = false;
  writable = true;
  [bt] = false;
  [gt] = false;
  [te] = false;
  [Y] = [];
  [ke] = false;
  [U];
  [ie];
  [ht];
  [m];
  [Me];
  [tt];
  [Ni] = false;
  [ot];
  constructor(t, e) {
    e = e || {}, super(e), this[U] = t, this[m] = typeof e.fd == "number" ? e.fd : void 0, this[ie] = e.mode === void 0 ? 438 : e.mode, this[ot] = typeof e.start == "number" ? e.start : void 0, this[ht] = typeof e.autoClose == "boolean" ? e.autoClose : true;
    let i = this[ot] !== void 0 ? "r+" : "w";
    this[Me] = e.flags === void 0, this[tt] = e.flags === void 0 ? i : e.flags, this[m] === void 0 && this[at]();
  }
  emit(t, ...e) {
    if (t === "error") {
      if (this[bt]) return false;
      this[bt] = true;
    }
    return super.emit(t, ...e);
  }
  get fd() {
    return this[m];
  }
  get path() {
    return this[U];
  }
  [Ut](t) {
    this[H](), this[gt] = true, this.emit("error", t);
  }
  [at]() {
    I.open(this[U], this[tt], this[ie], (t, e) => this[Ht](t, e));
  }
  [Ht](t, e) {
    this[Me] && this[tt] === "r+" && t && t.code === "ENOENT" ? (this[tt] = "w", this[at]()) : t ? this[Ut](t) : (this[m] = e, this.emit("open", e), this[gt] || this[Ai]());
  }
  end(t, e) {
    return t && this.write(t, e), this[te] = true, !this[gt] && !this[Y].length && typeof this[m] == "number" && this[Pt](null, 0), this;
  }
  write(t, e) {
    return typeof t == "string" && (t = Buffer.from(t, e)), this[te] ? (this.emit("error", new Error("write() after end()")), false) : this[m] === void 0 || this[gt] || this[Y].length ? (this[Y].push(t), this[ke] = true, false) : (this[gt] = true, this[ve](t), true);
  }
  [ve](t) {
    I.write(this[m], t, 0, t.length, this[ot], (e, i) => this[Pt](e, i));
  }
  [Pt](t, e) {
    t ? this[Ut](t) : (this[ot] !== void 0 && typeof e == "number" && (this[ot] += e), this[Y].length ? this[Ai]() : (this[gt] = false, this[te] && !this[Ni] ? (this[Ni] = true, this[H](), this.emit("finish")) : this[ke] && (this[ke] = false, this.emit("drain"))));
  }
  [Ai]() {
    if (this[Y].length === 0) this[te] && this[Pt](null, 0);
    else if (this[Y].length === 1) this[ve](this[Y].pop());
    else {
      let t = this[Y];
      this[Y] = [], Jr(this[m], t, this[ot], (e, i) => this[Pt](e, i));
    }
  }
  [H]() {
    if (this[ht] && typeof this[m] == "number") {
      let t = this[m];
      this[m] = void 0, I.close(t, (e) => e ? this.emit("error", e) : this.emit("close"));
    }
  }
};
var Wt = class extends et {
  [at]() {
    let t;
    if (this[Me] && this[tt] === "r+") try {
      t = I.openSync(this[U], this[tt], this[ie]);
    } catch (e) {
      if (e?.code === "ENOENT") return this[tt] = "w", this[at]();
      throw e;
    }
    else t = I.openSync(this[U], this[tt], this[ie]);
    this[Ht](null, t);
  }
  [H]() {
    if (this[ht] && typeof this[m] == "number") {
      let t = this[m];
      this[m] = void 0, I.closeSync(t), this.emit("close");
    }
  }
  [ve](t) {
    let e = true;
    try {
      this[Pt](null, I.writeSync(this[m], t, 0, t.length, this[ot])), e = false;
    } finally {
      if (e) try {
        this[H]();
      } catch {
      }
    }
  }
};
var jr = /* @__PURE__ */ new Map([["C", "cwd"], ["f", "file"], ["z", "gzip"], ["P", "preservePaths"], ["U", "unlink"], ["strip-components", "strip"], ["stripComponents", "strip"], ["keep-newer", "newer"], ["keepNewer", "newer"], ["keep-newer-files", "newer"], ["keepNewerFiles", "newer"], ["k", "keep"], ["keep-existing", "keep"], ["keepExisting", "keep"], ["m", "noMtime"], ["no-mtime", "noMtime"], ["p", "preserveOwner"], ["L", "follow"], ["h", "follow"], ["onentry", "onReadEntry"]]);
var Fs = (s3) => !!s3.sync && !!s3.file;
var ks = (s3) => !s3.sync && !!s3.file;
var vs = (s3) => !!s3.sync && !s3.file;
var Ms = (s3) => !s3.sync && !s3.file;
var Bs = (s3) => !!s3.file;
var tn = (s3) => {
  let t = jr.get(s3);
  return t || s3;
};
var se = (s3 = {}) => {
  if (!s3) return {};
  let t = {};
  for (let [e, i] of Object.entries(s3)) {
    let r = tn(e);
    t[r] = i;
  }
  return t.chmod === void 0 && t.noChmod === false && (t.chmod = true), delete t.noChmod, t;
};
var K = (s3, t, e, i, r) => Object.assign((n = [], o, h) => {
  Array.isArray(n) && (o = n, n = {}), typeof o == "function" && (h = o, o = void 0), o = o ? Array.from(o) : [];
  let a = se(n);
  if (r?.(a, o), Fs(a)) {
    if (typeof h == "function") throw new TypeError("callback not supported for sync tar functions");
    return s3(a, o);
  } else if (ks(a)) {
    let l = t(a, o);
    return h ? l.then(() => h(), h) : l;
  } else if (vs(a)) {
    if (typeof h == "function") throw new TypeError("callback not supported for sync tar functions");
    return e(a, o);
  } else if (Ms(a)) {
    if (typeof h == "function") throw new TypeError("callback only supported with file option");
    return i(a, o);
  }
  throw new Error("impossible options??");
}, { syncFile: s3, asyncFile: t, syncNoFile: e, asyncNoFile: i, validate: r });
var sn = en.constants || { ZLIB_VERNUM: 4736 };
var M = Object.freeze(Object.assign(/* @__PURE__ */ Object.create(null), { Z_NO_FLUSH: 0, Z_PARTIAL_FLUSH: 1, Z_SYNC_FLUSH: 2, Z_FULL_FLUSH: 3, Z_FINISH: 4, Z_BLOCK: 5, Z_OK: 0, Z_STREAM_END: 1, Z_NEED_DICT: 2, Z_ERRNO: -1, Z_STREAM_ERROR: -2, Z_DATA_ERROR: -3, Z_MEM_ERROR: -4, Z_BUF_ERROR: -5, Z_VERSION_ERROR: -6, Z_NO_COMPRESSION: 0, Z_BEST_SPEED: 1, Z_BEST_COMPRESSION: 9, Z_DEFAULT_COMPRESSION: -1, Z_FILTERED: 1, Z_HUFFMAN_ONLY: 2, Z_RLE: 3, Z_FIXED: 4, Z_DEFAULT_STRATEGY: 0, DEFLATE: 1, INFLATE: 2, GZIP: 3, GUNZIP: 4, DEFLATERAW: 5, INFLATERAW: 6, UNZIP: 7, BROTLI_DECODE: 8, BROTLI_ENCODE: 9, Z_MIN_WINDOWBITS: 8, Z_MAX_WINDOWBITS: 15, Z_DEFAULT_WINDOWBITS: 15, Z_MIN_CHUNK: 64, Z_MAX_CHUNK: 1 / 0, Z_DEFAULT_CHUNK: 16384, Z_MIN_MEMLEVEL: 1, Z_MAX_MEMLEVEL: 9, Z_DEFAULT_MEMLEVEL: 8, Z_MIN_LEVEL: -1, Z_MAX_LEVEL: 9, Z_DEFAULT_LEVEL: -1, BROTLI_OPERATION_PROCESS: 0, BROTLI_OPERATION_FLUSH: 1, BROTLI_OPERATION_FINISH: 2, BROTLI_OPERATION_EMIT_METADATA: 3, BROTLI_MODE_GENERIC: 0, BROTLI_MODE_TEXT: 1, BROTLI_MODE_FONT: 2, BROTLI_DEFAULT_MODE: 0, BROTLI_MIN_QUALITY: 0, BROTLI_MAX_QUALITY: 11, BROTLI_DEFAULT_QUALITY: 11, BROTLI_MIN_WINDOW_BITS: 10, BROTLI_MAX_WINDOW_BITS: 24, BROTLI_LARGE_MAX_WINDOW_BITS: 30, BROTLI_DEFAULT_WINDOW: 22, BROTLI_MIN_INPUT_BLOCK_BITS: 16, BROTLI_MAX_INPUT_BLOCK_BITS: 24, BROTLI_PARAM_MODE: 0, BROTLI_PARAM_QUALITY: 1, BROTLI_PARAM_LGWIN: 2, BROTLI_PARAM_LGBLOCK: 3, BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING: 4, BROTLI_PARAM_SIZE_HINT: 5, BROTLI_PARAM_LARGE_WINDOW: 6, BROTLI_PARAM_NPOSTFIX: 7, BROTLI_PARAM_NDIRECT: 8, BROTLI_DECODER_RESULT_ERROR: 0, BROTLI_DECODER_RESULT_SUCCESS: 1, BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: 2, BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: 3, BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION: 0, BROTLI_DECODER_PARAM_LARGE_WINDOW: 1, BROTLI_DECODER_NO_ERROR: 0, BROTLI_DECODER_SUCCESS: 1, BROTLI_DECODER_NEEDS_MORE_INPUT: 2, BROTLI_DECODER_NEEDS_MORE_OUTPUT: 3, BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE: -1, BROTLI_DECODER_ERROR_FORMAT_RESERVED: -2, BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_META_NIBBLE: -3, BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET: -4, BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME: -5, BROTLI_DECODER_ERROR_FORMAT_CL_SPACE: -6, BROTLI_DECODER_ERROR_FORMAT_HUFFMAN_SPACE: -7, BROTLI_DECODER_ERROR_FORMAT_CONTEXT_MAP_REPEAT: -8, BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_1: -9, BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_2: -10, BROTLI_DECODER_ERROR_FORMAT_TRANSFORM: -11, BROTLI_DECODER_ERROR_FORMAT_DICTIONARY: -12, BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS: -13, BROTLI_DECODER_ERROR_FORMAT_PADDING_1: -14, BROTLI_DECODER_ERROR_FORMAT_PADDING_2: -15, BROTLI_DECODER_ERROR_FORMAT_DISTANCE: -16, BROTLI_DECODER_ERROR_DICTIONARY_NOT_SET: -19, BROTLI_DECODER_ERROR_INVALID_ARGUMENTS: -20, BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES: -21, BROTLI_DECODER_ERROR_ALLOC_TREE_GROUPS: -22, BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MAP: -25, BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_1: -26, BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_2: -27, BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES: -30, BROTLI_DECODER_ERROR_UNREACHABLE: -31 }, sn));
var rn = Ot.concat;
var zs = Object.getOwnPropertyDescriptor(Ot, "concat");
var nn = (s3) => s3;
var Bi = zs?.writable === true || zs?.set !== void 0 ? (s3) => {
  Ot.concat = s3 ? nn : rn;
} : (s3) => {
};
var Tt = /* @__PURE__ */ Symbol("_superWrite");
var Gt = class extends Error {
  code;
  errno;
  constructor(t, e) {
    super("zlib: " + t.message, { cause: t }), this.code = t.code, this.errno = t.errno, this.code || (this.code = "ZLIB_ERROR"), this.message = "zlib: " + t.message, Error.captureStackTrace(this, e ?? this.constructor);
  }
  get name() {
    return "ZlibError";
  }
};
var Pi = /* @__PURE__ */ Symbol("flushFlag");
var re = class extends A {
  #t = false;
  #i = false;
  #s;
  #n;
  #r;
  #e;
  #o;
  get sawError() {
    return this.#t;
  }
  get handle() {
    return this.#e;
  }
  get flushFlag() {
    return this.#s;
  }
  constructor(t, e) {
    if (!t || typeof t != "object") throw new TypeError("invalid options for ZlibBase constructor");
    if (super(t), this.#s = t.flush ?? 0, this.#n = t.finishFlush ?? 0, this.#r = t.fullFlushFlag ?? 0, typeof Ps[e] != "function") throw new TypeError("Compression method not supported: " + e);
    try {
      this.#e = new Ps[e](t);
    } catch (i) {
      throw new Gt(i, this.constructor);
    }
    this.#o = (i) => {
      this.#t || (this.#t = true, this.close(), this.emit("error", i));
    }, this.#e?.on("error", (i) => this.#o(new Gt(i))), this.once("end", () => this.close);
  }
  close() {
    this.#e && (this.#e.close(), this.#e = void 0, this.emit("close"));
  }
  reset() {
    if (!this.#t) return zi(this.#e, "zlib binding closed"), this.#e.reset?.();
  }
  flush(t) {
    this.ended || (typeof t != "number" && (t = this.#r), this.write(Object.assign(Ot.alloc(0), { [Pi]: t })));
  }
  end(t, e, i) {
    return typeof t == "function" && (i = t, e = void 0, t = void 0), typeof e == "function" && (i = e, e = void 0), t && (e ? this.write(t, e) : this.write(t)), this.flush(this.#n), this.#i = true, super.end(i);
  }
  get ended() {
    return this.#i;
  }
  [Tt](t) {
    return super.write(t);
  }
  write(t, e, i) {
    if (typeof e == "function" && (i = e, e = "utf8"), typeof t == "string" && (t = Ot.from(t, e)), this.#t) return;
    zi(this.#e, "zlib binding closed");
    let r = this.#e._handle, n = r.close;
    r.close = () => {
    };
    let o = this.#e.close;
    this.#e.close = () => {
    }, Bi(true);
    let h;
    try {
      let l = typeof t[Pi] == "number" ? t[Pi] : this.#s;
      h = this.#e._processChunk(t, l), Bi(false);
    } catch (l) {
      Bi(false), this.#o(new Gt(l, this.write));
    } finally {
      this.#e && (this.#e._handle = r, r.close = n, this.#e.close = o, this.#e.removeAllListeners("error"));
    }
    this.#e && this.#e.on("error", (l) => this.#o(new Gt(l, this.write)));
    let a;
    if (h) if (Array.isArray(h) && h.length > 0) {
      let l = h[0];
      a = this[Tt](Ot.from(l));
      for (let c = 1; c < h.length; c++) a = this[Tt](h[c]);
    } else a = this[Tt](Ot.from(h));
    return i && i(), a;
  }
};
var Pe = class extends re {
  #t;
  #i;
  constructor(t, e) {
    t = t || {}, t.flush = t.flush || M.Z_NO_FLUSH, t.finishFlush = t.finishFlush || M.Z_FINISH, t.fullFlushFlag = M.Z_FULL_FLUSH, super(t, e), this.#t = t.level, this.#i = t.strategy;
  }
  params(t, e) {
    if (!this.sawError) {
      if (!this.handle) throw new Error("cannot switch params when binding is closed");
      if (!this.handle.params) throw new Error("not supported in this implementation");
      if (this.#t !== t || this.#i !== e) {
        this.flush(M.Z_SYNC_FLUSH), zi(this.handle, "zlib binding closed");
        let i = this.handle.flush;
        this.handle.flush = (r, n) => {
          typeof r == "function" && (n = r, r = this.flushFlag), this.flush(r), n?.();
        };
        try {
          this.handle.params(t, e);
        } finally {
          this.handle.flush = i;
        }
        this.handle && (this.#t = t, this.#i = e);
      }
    }
  }
};
var ze = class extends Pe {
  #t;
  constructor(t) {
    super(t, "Gzip"), this.#t = t && !!t.portable;
  }
  [Tt](t) {
    return this.#t ? (this.#t = false, t[9] = 255, super[Tt](t)) : super[Tt](t);
  }
};
var Ue = class extends Pe {
  constructor(t) {
    super(t, "Unzip");
  }
};
var He = class extends re {
  constructor(t, e) {
    t = t || {}, t.flush = t.flush || M.BROTLI_OPERATION_PROCESS, t.finishFlush = t.finishFlush || M.BROTLI_OPERATION_FINISH, t.fullFlushFlag = M.BROTLI_OPERATION_FLUSH, super(t, e);
  }
};
var We = class extends He {
  constructor(t) {
    super(t, "BrotliCompress");
  }
};
var Ge = class extends He {
  constructor(t) {
    super(t, "BrotliDecompress");
  }
};
var Ze = class extends re {
  constructor(t, e) {
    t = t || {}, t.flush = t.flush || M.ZSTD_e_continue, t.finishFlush = t.finishFlush || M.ZSTD_e_end, t.fullFlushFlag = M.ZSTD_e_flush, super(t, e);
  }
};
var Ye = class extends Ze {
  constructor(t) {
    super(t, "ZstdCompress");
  }
};
var Ke = class extends Ze {
  constructor(t) {
    super(t, "ZstdDecompress");
  }
};
var Us = (s3, t) => {
  if (Number.isSafeInteger(s3)) s3 < 0 ? an(s3, t) : hn(s3, t);
  else throw Error("cannot encode number outside of javascript safe integer range");
  return t;
};
var hn = (s3, t) => {
  t[0] = 128;
  for (var e = t.length; e > 1; e--) t[e - 1] = s3 & 255, s3 = Math.floor(s3 / 256);
};
var an = (s3, t) => {
  t[0] = 255;
  var e = false;
  s3 = s3 * -1;
  for (var i = t.length; i > 1; i--) {
    var r = s3 & 255;
    s3 = Math.floor(s3 / 256), e ? t[i - 1] = Ws(r) : r === 0 ? t[i - 1] = 0 : (e = true, t[i - 1] = Gs(r));
  }
};
var Hs = (s3) => {
  let t = s3[0], e = t === 128 ? cn(s3.subarray(1, s3.length)) : t === 255 ? ln(s3) : null;
  if (e === null) throw Error("invalid base256 encoding");
  if (!Number.isSafeInteger(e)) throw Error("parsed number outside of javascript safe integer range");
  return e;
};
var ln = (s3) => {
  for (var t = s3.length, e = 0, i = false, r = t - 1; r > -1; r--) {
    var n = Number(s3[r]), o;
    i ? o = Ws(n) : n === 0 ? o = n : (i = true, o = Gs(n)), o !== 0 && (e -= o * Math.pow(256, t - r - 1));
  }
  return e;
};
var cn = (s3) => {
  for (var t = s3.length, e = 0, i = t - 1; i > -1; i--) {
    var r = Number(s3[i]);
    r !== 0 && (e += r * Math.pow(256, t - i - 1));
  }
  return e;
};
var Ws = (s3) => (255 ^ s3) & 255;
var Gs = (s3) => (255 ^ s3) + 1 & 255;
var Hi = {};
Ur(Hi, { code: () => Ve, isCode: () => ne, isName: () => dn, name: () => oe, normalFsTypes: () => Ui });
var ne = (s3) => oe.has(s3);
var dn = (s3) => Ve.has(s3);
var Ui = /* @__PURE__ */ new Set(["0", "", "1", "2", "3", "4", "5", "6", "7", "D"]);
var oe = /* @__PURE__ */ new Map([["0", "File"], ["", "OldFile"], ["1", "Link"], ["2", "SymbolicLink"], ["3", "CharacterDevice"], ["4", "BlockDevice"], ["5", "Directory"], ["6", "FIFO"], ["7", "ContiguousFile"], ["g", "GlobalExtendedHeader"], ["x", "ExtendedHeader"], ["A", "SolarisACL"], ["D", "GNUDumpDir"], ["I", "Inode"], ["K", "NextFileHasLongLinkpath"], ["L", "NextFileHasLongPath"], ["M", "ContinuationFile"], ["N", "OldGnuLongPath"], ["S", "SparseFile"], ["V", "TapeVolumeHeader"], ["X", "OldExtendedHeader"]]);
var Ve = new Map(Array.from(oe).map((s3) => [s3[1], s3[0]]));
var un = (s3) => s3 === void 0 || s3 < 0 ? void 0 : s3;
var F = class {
  cksumValid = false;
  needPax = false;
  nullBlock = false;
  block;
  path;
  mode;
  uid;
  gid;
  size;
  cksum;
  #t = "Unsupported";
  linkpath;
  uname;
  gname;
  devmaj = 0;
  devmin = 0;
  atime;
  ctime;
  mtime;
  charset;
  comment;
  constructor(t, e = 0, i, r) {
    Buffer.isBuffer(t) ? this.decode(t, e || 0, i, r) : t && this.#i(t);
  }
  decode(t, e, i, r) {
    if (e || (e = 0), !t || !(t.length >= e + 512)) throw new Error("need 512 bytes for header");
    let n = xt(t, e + 156, 1), o = Ui.has(n), h = o ? i : void 0, a = o ? r : void 0;
    if (this.path = h?.path ?? xt(t, e, 100), this.mode = h?.mode ?? a?.mode ?? lt(t, e + 100, 8), this.uid = h?.uid ?? a?.uid ?? lt(t, e + 108, 8), this.gid = h?.gid ?? a?.gid ?? lt(t, e + 116, 8), this.size = un(h?.size ?? a?.size ?? lt(t, e + 124, 12)), this.mtime = h?.mtime ?? a?.mtime ?? Wi(t, e + 136, 12), this.cksum = lt(t, e + 148, 12), a && this.#i(a, true), h && this.#i(h), ne(n) && (this.#t = n || "0"), this.#t === "0" && this.path.slice(-1) === "/" && (this.#t = "5"), this.#t === "5" && (this.size = 0), this.linkpath = xt(t, e + 157, 100), t.subarray(e + 257, e + 265).toString() === "ustar\x0000") if (this.uname = h?.uname ?? a?.uname ?? xt(t, e + 265, 32), this.gname = h?.gname ?? a?.gname ?? xt(t, e + 297, 32), this.devmaj = h?.devmaj ?? a?.devmaj ?? lt(t, e + 329, 8) ?? 0, this.devmin = h?.devmin ?? a?.devmin ?? lt(t, e + 337, 8) ?? 0, t[e + 475] !== 0) {
      let c = xt(t, e + 345, 155);
      this.path = c + "/" + this.path;
    } else {
      let c = xt(t, e + 345, 130);
      c && (this.path = c + "/" + this.path), this.atime = i?.atime ?? r?.atime ?? Wi(t, e + 476, 12), this.ctime = i?.ctime ?? r?.ctime ?? Wi(t, e + 488, 12);
    }
    let l = 256;
    for (let c = e; c < e + 148; c++) l += t[c];
    for (let c = e + 156; c < e + 512; c++) l += t[c];
    this.cksumValid = l === this.cksum, this.cksum === void 0 && l === 256 && (this.nullBlock = true);
  }
  #i(t, e = false) {
    Object.assign(this, Object.fromEntries(Object.entries(t).filter(([i, r]) => !(r == null || i === "size" && Number(r) < 0 || i === "path" && e || i === "linkpath" && e || i === "global"))));
  }
  encode(t, e = 0) {
    if (t || (t = this.block = Buffer.alloc(512)), this.#t === "Unsupported" && (this.#t = "0"), !(t.length >= e + 512)) throw new Error("need 512 bytes for header");
    let i = this.ctime || this.atime ? 130 : 155, r = mn(this.path || "", i), n = r[0], o = r[1];
    this.needPax = !!r[2], this.needPax = Lt(t, e, 100, n) || this.needPax, this.needPax = ct(t, e + 100, 8, this.mode) || this.needPax, this.needPax = ct(t, e + 108, 8, this.uid) || this.needPax, this.needPax = ct(t, e + 116, 8, this.gid) || this.needPax, this.needPax = ct(t, e + 124, 12, this.size) || this.needPax, this.needPax = Gi(t, e + 136, 12, this.mtime) || this.needPax, t[e + 156] = Number(this.#t.codePointAt(0)), this.needPax = Lt(t, e + 157, 100, this.linkpath) || this.needPax, t.write("ustar\x0000", e + 257, 8), this.needPax = Lt(t, e + 265, 32, this.uname) || this.needPax, this.needPax = Lt(t, e + 297, 32, this.gname) || this.needPax, this.needPax = ct(t, e + 329, 8, this.devmaj) || this.needPax, this.needPax = ct(t, e + 337, 8, this.devmin) || this.needPax, this.needPax = Lt(t, e + 345, i, o) || this.needPax, t[e + 475] !== 0 ? this.needPax = Lt(t, e + 345, 155, o) || this.needPax : (this.needPax = Lt(t, e + 345, 130, o) || this.needPax, this.needPax = Gi(t, e + 476, 12, this.atime) || this.needPax, this.needPax = Gi(t, e + 488, 12, this.ctime) || this.needPax);
    let h = 256;
    for (let a = e; a < e + 148; a++) h += t[a];
    for (let a = e + 156; a < e + 512; a++) h += t[a];
    return this.cksum = h, ct(t, e + 148, 8, this.cksum), this.cksumValid = true, this.needPax;
  }
  get type() {
    return this.#t === "Unsupported" ? this.#t : oe.get(this.#t);
  }
  get typeKey() {
    return this.#t;
  }
  set type(t) {
    let e = String(Ve.get(t));
    if (ne(e) || e === "Unsupported") this.#t = e;
    else if (ne(t)) this.#t = t;
    else throw new TypeError("invalid entry type: " + t);
  }
};
var mn = (s3, t) => {
  let i = s3, r = "", n, o = Zt.parse(s3).root || ".";
  if (Buffer.byteLength(i) < 100) n = [i, r, false];
  else {
    r = Zt.dirname(i), i = Zt.basename(i);
    do
      Buffer.byteLength(i) <= 100 && Buffer.byteLength(r) <= t ? n = [i, r, false] : Buffer.byteLength(i) > 100 && Buffer.byteLength(r) <= t ? n = [i.slice(0, 99), r, true] : (i = Zt.join(Zt.basename(r), i), r = Zt.dirname(r));
    while (r !== o && n === void 0);
    n || (n = [s3.slice(0, 99), "", true]);
  }
  return n;
};
var xt = (s3, t, e) => s3.subarray(t, t + e).toString("utf8").replace(/\0.*/, "");
var Wi = (s3, t, e) => pn(lt(s3, t, e));
var pn = (s3) => s3 === void 0 ? void 0 : new Date(s3 * 1e3);
var lt = (s3, t, e) => Number(s3[t]) & 128 ? Hs(s3.subarray(t, t + e)) : wn(s3, t, e);
var En = (s3) => isNaN(s3) ? void 0 : s3;
var wn = (s3, t, e) => En(parseInt(s3.subarray(t, t + e).toString("utf8").replace(/\0.*$/, "").trim(), 8));
var Sn = { 12: 8589934591, 8: 2097151 };
var ct = (s3, t, e, i) => i === void 0 ? false : i > Sn[e] || i < 0 ? (Us(i, s3.subarray(t, t + e)), true) : (yn(s3, t, e, i), false);
var yn = (s3, t, e, i) => s3.write(Rn(i, e), t, e, "ascii");
var Rn = (s3, t) => gn(Math.floor(s3).toString(8), t);
var gn = (s3, t) => (s3.length === t - 1 ? s3 : new Array(t - s3.length - 1).join("0") + s3 + " ") + "\0";
var Gi = (s3, t, e, i) => i === void 0 ? false : ct(s3, t, e, i.getTime() / 1e3);
var bn = new Array(156).join("\0");
var Lt = (s3, t, e, i) => i === void 0 ? false : (s3.write(i + bn, t, e, "utf8"), i.length !== Buffer.byteLength(i) || i.length > e);
var ft = class s {
  atime;
  mtime;
  ctime;
  charset;
  comment;
  gid;
  uid;
  gname;
  uname;
  linkpath;
  dev;
  ino;
  nlink;
  path;
  size;
  mode;
  global;
  constructor(t, e = false) {
    this.atime = t.atime, this.charset = t.charset, this.comment = t.comment, this.ctime = t.ctime, this.dev = t.dev, this.gid = t.gid, this.global = e, this.gname = t.gname, this.ino = t.ino, this.linkpath = t.linkpath, this.mtime = t.mtime, this.nlink = t.nlink, this.path = t.path, this.size = t.size, this.uid = t.uid, this.uname = t.uname;
  }
  encode() {
    let t = this.encodeBody();
    if (t === "") return Buffer.allocUnsafe(0);
    let e = Buffer.byteLength(t), i = 512 * Math.ceil(1 + e / 512), r = Buffer.allocUnsafe(i);
    for (let n = 0; n < 512; n++) r[n] = 0;
    new F({ path: ("PaxHeader/" + _n(this.path ?? "")).slice(0, 99), mode: this.mode || 420, uid: this.uid, gid: this.gid, size: e, mtime: this.mtime, type: this.global ? "GlobalExtendedHeader" : "ExtendedHeader", linkpath: "", uname: this.uname || "", gname: this.gname || "", devmaj: 0, devmin: 0, atime: this.atime, ctime: this.ctime }).encode(r), r.write(t, 512, e, "utf8");
    for (let n = e + 512; n < r.length; n++) r[n] = 0;
    return r;
  }
  encodeBody() {
    return this.encodeField("path") + this.encodeField("ctime") + this.encodeField("atime") + this.encodeField("dev") + this.encodeField("ino") + this.encodeField("nlink") + this.encodeField("charset") + this.encodeField("comment") + this.encodeField("gid") + this.encodeField("gname") + this.encodeField("linkpath") + this.encodeField("mtime") + this.encodeField("size") + this.encodeField("uid") + this.encodeField("uname");
  }
  encodeField(t) {
    if (this[t] === void 0) return "";
    let e = this[t], i = e instanceof Date ? e.getTime() / 1e3 : e, r = " " + (t === "dev" || t === "ino" || t === "nlink" ? "SCHILY." : "") + t + "=" + i + `
`, n = Buffer.byteLength(r), o = Math.floor(Math.log(n) / Math.log(10)) + 1;
    return n + o >= Math.pow(10, o) && (o += 1), o + n + r;
  }
  static parse(t, e, i = false) {
    return new s(On(Tn(t), e), i);
  }
};
var On = (s3, t) => t ? Object.assign({}, t, s3) : s3;
var Tn = (s3) => s3.replace(/\n$/, "").split(`
`).reduce(xn, /* @__PURE__ */ Object.create(null));
var xn = (s3, t) => {
  let e = parseInt(t, 10);
  if (e !== Buffer.byteLength(t) + 1) return s3;
  t = t.slice((e + " ").length);
  let i = t.split("="), r = i.shift();
  if (!r) return s3;
  let n = r.replace(/^SCHILY\.(dev|ino|nlink)/, "$1"), o = i.join("=").replace(/\0.*/, "");
  switch (n) {
    case "path":
    case "linkpath":
    case "type":
    case "charset":
    case "comment":
    case "gname":
    case "uname":
      s3[n] = o;
      break;
    case "ctime":
    case "atime":
    case "mtime":
      s3[n] = new Date(Number(o) * 1e3);
      break;
    case "size":
      let h = +o;
      h >= 0 && (s3[n] = h);
      break;
    case "gid":
    case "uid":
    case "dev":
    case "ino":
    case "nlink":
    case "mode":
      s3[n] = +o;
      break;
  }
  return s3;
};
var Ln = process.env.TESTING_TAR_FAKE_PLATFORM || process.platform;
var f = Ln !== "win32" ? (s3) => String(s3) : (s3) => String(s3).replaceAll(/\\/g, "/");
var $e = class extends A {
  extended;
  globalExtended;
  header;
  startBlockSize;
  blockRemain;
  remain;
  type;
  meta = false;
  ignore = false;
  path;
  mode;
  uid;
  gid;
  uname;
  gname;
  size = 0;
  mtime;
  atime;
  ctime;
  linkpath;
  dev;
  ino;
  nlink;
  invalid = false;
  absolute;
  unsupported = false;
  constructor(t, e, i) {
    switch (super({}), this.pause(), this.extended = e, this.globalExtended = i, this.header = t, this.remain = t.size ?? 0, this.startBlockSize = 512 * Math.ceil(this.remain / 512), this.blockRemain = this.startBlockSize, this.type = t.type, this.type) {
      case "File":
      case "OldFile":
      case "Link":
      case "SymbolicLink":
      case "CharacterDevice":
      case "BlockDevice":
      case "Directory":
      case "FIFO":
      case "ContiguousFile":
      case "GNUDumpDir":
        break;
      case "NextFileHasLongLinkpath":
      case "NextFileHasLongPath":
      case "OldGnuLongPath":
      case "GlobalExtendedHeader":
      case "ExtendedHeader":
      case "OldExtendedHeader":
        this.meta = true;
        break;
      default:
        this.ignore = true;
    }
    if (!t.path) throw new Error("no path provided for tar.ReadEntry");
    this.path = f(t.path), this.mode = t.mode, this.mode && (this.mode = this.mode & 4095), this.uid = t.uid, this.gid = t.gid, this.uname = t.uname, this.gname = t.gname, this.size = this.remain, this.mtime = t.mtime, this.atime = t.atime, this.ctime = t.ctime, this.linkpath = t.linkpath ? f(t.linkpath) : void 0, this.uname = t.uname, this.gname = t.gname, e && this.#t(e), i && this.#t(i, true);
  }
  write(t) {
    let e = t.length;
    if (e > this.blockRemain) throw new Error("writing more to entry than is appropriate");
    let i = this.remain, r = this.blockRemain;
    return this.remain = Math.max(0, i - e), this.blockRemain = Math.max(0, r - e), this.ignore ? true : i >= e ? super.write(t) : super.write(t.subarray(0, i));
  }
  #t(t, e = false) {
    t.path && (t.path = f(t.path)), t.linkpath && (t.linkpath = f(t.linkpath)), Object.assign(this, Object.fromEntries(Object.entries(t).filter(([i, r]) => !(r == null || i === "path" && e))));
  }
};
var Dt = (s3, t, e, i = {}) => {
  s3.file && (i.file = s3.file), s3.cwd && (i.cwd = s3.cwd), i.code = e instanceof Error && e.code || t, i.tarCode = t, !s3.strict && i.recoverable !== false ? (e instanceof Error && (i = Object.assign(e, i), e = e.message), s3.emit("warn", t, e, i)) : e instanceof Error ? s3.emit("error", Object.assign(e, i)) : s3.emit("error", Object.assign(new Error(`${t}: ${e}`), i));
};
var Nn = 1024 * 1024;
var Xi = Buffer.from([31, 139]);
var qi = Buffer.from([40, 181, 47, 253]);
var An = Math.max(Xi.length, qi.length);
var B = /* @__PURE__ */ Symbol("state");
var Nt = /* @__PURE__ */ Symbol("writeEntry");
var it = /* @__PURE__ */ Symbol("readEntry");
var Zi = /* @__PURE__ */ Symbol("nextEntry");
var Zs = /* @__PURE__ */ Symbol("processEntry");
var V = /* @__PURE__ */ Symbol("extendedHeader");
var he = /* @__PURE__ */ Symbol("globalExtendedHeader");
var dt = /* @__PURE__ */ Symbol("meta");
var Ys = /* @__PURE__ */ Symbol("emitMeta");
var p = /* @__PURE__ */ Symbol("buffer");
var st = /* @__PURE__ */ Symbol("queue");
var ut = /* @__PURE__ */ Symbol("ended");
var Yi = /* @__PURE__ */ Symbol("emittedEnd");
var At = /* @__PURE__ */ Symbol("emit");
var w = /* @__PURE__ */ Symbol("unzip");
var Xe = /* @__PURE__ */ Symbol("consumeChunk");
var qe = /* @__PURE__ */ Symbol("consumeChunkSub");
var Ki = /* @__PURE__ */ Symbol("consumeBody");
var Ks = /* @__PURE__ */ Symbol("consumeMeta");
var Vs = /* @__PURE__ */ Symbol("consumeHeader");
var ae = /* @__PURE__ */ Symbol("consuming");
var Vi = /* @__PURE__ */ Symbol("bufferConcat");
var Qe = /* @__PURE__ */ Symbol("maybeEnd");
var Yt = /* @__PURE__ */ Symbol("writing");
var $ = /* @__PURE__ */ Symbol("aborted");
var Je = /* @__PURE__ */ Symbol("onDone");
var It = /* @__PURE__ */ Symbol("sawValidEntry");
var je = /* @__PURE__ */ Symbol("sawNullBlock");
var ti = /* @__PURE__ */ Symbol("sawEOF");
var $s = /* @__PURE__ */ Symbol("closeStream");
var In = 1e3;
var le = /* @__PURE__ */ Symbol("compressedBytesRead");
var $i = /* @__PURE__ */ Symbol("decompressedBytesRead");
var Xs = /* @__PURE__ */ Symbol("checkDecompressionRatio");
var Cn = () => true;
var rt = class extends Dn {
  file;
  strict;
  maxMetaEntrySize;
  filter;
  brotli;
  zstd;
  maxDecompressionRatio;
  writable = true;
  readable = false;
  [st] = [];
  [p];
  [it];
  [Nt];
  [B] = "begin";
  [dt] = "";
  [V];
  [he];
  [ut] = false;
  [w];
  [$] = false;
  [It];
  [je] = false;
  [ti] = false;
  [Yt] = false;
  [ae] = false;
  [Yi] = false;
  [le] = 0;
  [$i] = 0;
  constructor(t = {}) {
    super(), this.file = t.file || "", this.on(Je, () => {
      (this[B] === "begin" || this[It] === false) && this.warn("TAR_BAD_ARCHIVE", "Unrecognized archive format");
    }), t.ondone ? this.on(Je, t.ondone) : this.on(Je, () => {
      this.emit("prefinish"), this.emit("finish"), this.emit("end");
    }), this.strict = !!t.strict, this.maxDecompressionRatio = typeof t.maxDecompressionRatio == "number" ? t.maxDecompressionRatio : In, this.maxMetaEntrySize = t.maxMetaEntrySize || Nn, this.filter = typeof t.filter == "function" ? t.filter : Cn;
    let e = t.file && (t.file.endsWith(".tar.br") || t.file.endsWith(".tbr"));
    this.brotli = !(t.gzip || t.zstd) && t.brotli !== void 0 ? t.brotli : e ? void 0 : false;
    let i = t.file && (t.file.endsWith(".tar.zst") || t.file.endsWith(".tzst"));
    this.zstd = !(t.gzip || t.brotli) && t.zstd !== void 0 ? t.zstd : i ? true : void 0, this.on("end", () => this[$s]()), typeof t.onwarn == "function" && this.on("warn", t.onwarn), typeof t.onReadEntry == "function" && this.on("entry", t.onReadEntry);
  }
  warn(t, e, i = {}) {
    Dt(this, t, e, i);
  }
  [Vs](t, e) {
    this[It] === void 0 && (this[It] = false);
    let i;
    try {
      i = new F(t, e, this[V], this[he]);
    } catch (r) {
      return this.warn("TAR_ENTRY_INVALID", r);
    }
    if (i.nullBlock) this[je] ? (this[ti] = true, this[B] === "begin" && (this[B] = "header"), this[At]("eof")) : (this[je] = true, this[At]("nullBlock"));
    else if (this[je] = false, !i.cksumValid) this.warn("TAR_ENTRY_INVALID", "checksum failure", { header: i });
    else if (!i.path) this.warn("TAR_ENTRY_INVALID", "path is required", { header: i });
    else {
      let r = i.type;
      if (/^(Symbolic)?Link$/.test(r) && !i.linkpath) this.warn("TAR_ENTRY_INVALID", "linkpath required", { header: i });
      else if (!/^(Symbolic)?Link$/.test(r) && !/^(Global)?ExtendedHeader$/.test(r) && i.linkpath) this.warn("TAR_ENTRY_INVALID", "linkpath forbidden", { header: i });
      else {
        let n = this[Nt] = new $e(i, this[V], this[he]);
        if (!this[It]) if (n.remain) {
          let o = () => {
            n.invalid || (this[It] = true);
          };
          n.on("end", o);
        } else this[It] = true;
        n.meta ? n.size > this.maxMetaEntrySize ? (n.ignore = true, this[At]("ignoredEntry", n), this[B] = "ignore", n.resume()) : n.size > 0 && (this[dt] = "", n.on("data", (o) => this[dt] += o), this[B] = "meta") : (this[V] = void 0, n.ignore = n.ignore || !this.filter(n.path, n), n.ignore ? (this[At]("ignoredEntry", n), this[B] = n.remain ? "ignore" : "header", n.resume()) : (n.remain ? this[B] = "body" : (this[B] = "header", n.end()), this[it] ? this[st].push(n) : (this[st].push(n), this[Zi]())));
      }
    }
  }
  [$s]() {
    queueMicrotask(() => this.emit("close"));
  }
  [Zs](t) {
    let e = true;
    if (!t) this[it] = void 0, e = false;
    else if (Array.isArray(t)) {
      let [i, ...r] = t;
      this.emit(i, ...r);
    } else this[it] = t, this.emit("entry", t), t.emittedEnd || (t.on("end", () => this[Zi]()), e = false);
    return e;
  }
  [Zi]() {
    do
      ;
    while (this[Zs](this[st].shift()));
    if (this[st].length === 0) {
      let t = this[it];
      !t || t.flowing || t.size === t.remain ? this[Yt] || this.emit("drain") : t.once("drain", () => this.emit("drain"));
    }
  }
  [Ki](t, e) {
    let i = this[Nt];
    if (!i) throw new Error("attempt to consume body without entry??");
    let r = i.blockRemain ?? 0, n = r >= t.length && e === 0 ? t : t.subarray(e, e + r);
    return i.write(n), i.blockRemain || (this[B] = "header", this[Nt] = void 0, i.end()), n.length;
  }
  [Ks](t, e) {
    let i = this[Nt], r = this[Ki](t, e);
    return !this[Nt] && i && this[Ys](i), r;
  }
  [At](t, e, i) {
    this[st].length === 0 && !this[it] ? this.emit(t, e, i) : this[st].push([t, e, i]);
  }
  [Ys](t) {
    switch (this[At]("meta", this[dt]), t.type) {
      case "ExtendedHeader":
      case "OldExtendedHeader":
        this[V] = ft.parse(this[dt], this[V], false);
        break;
      case "GlobalExtendedHeader":
        this[he] = ft.parse(this[dt], this[he], true);
        break;
      case "NextFileHasLongPath":
      case "OldGnuLongPath": {
        let e = this[V] ?? /* @__PURE__ */ Object.create(null);
        this[V] = e, e.path = this[dt].replace(/\0.*/, "");
        break;
      }
      case "NextFileHasLongLinkpath": {
        let e = this[V] || /* @__PURE__ */ Object.create(null);
        this[V] = e, e.linkpath = this[dt].replace(/\0.*/, "");
        break;
      }
      default:
        throw new Error("unknown meta: " + t.type);
    }
  }
  abort(t) {
    if (!this[$]) {
      if (this[w]) {
        let e = this[w];
        e.write = () => true, e.end = () => e, e.emit = () => false, e.destroy?.();
      }
      this[$] = true, this.emit("abort", t), this.warn("TAR_ABORT", t, { recoverable: false });
    }
  }
  [Xs](t) {
    this[$i] += t.length;
    let e = this[$i] / this[le];
    return e > this.maxDecompressionRatio ? (this.abort(new Error(`max decompression ratio exceeded: ${e.toFixed(2)} > ${this.maxDecompressionRatio}`)), false) : true;
  }
  write(t, e, i) {
    if (typeof e == "function" && (i = e, e = void 0), typeof t == "string" && (t = Buffer.from(t, typeof e == "string" ? e : "utf8")), this[$]) return i?.(), false;
    if ((this[w] === void 0 || this.brotli === void 0 && this[w] === false) && t) {
      if (this[p] && (t = Buffer.concat([this[p], t]), this[p] = void 0), t.length < An) return this[p] = t, i?.(), true;
      for (let a = 0; this[w] === void 0 && a < Xi.length; a++) t[a] !== Xi[a] && (this[w] = false);
      let o = false;
      if (this[w] === false && this.zstd !== false) {
        o = true;
        for (let a = 0; a < qi.length; a++) if (t[a] !== qi[a]) {
          o = false;
          break;
        }
      }
      let h = this.brotli === void 0 && !o;
      if (this[w] === false && h) if (t.length < 512) if (this[ut]) this.brotli = true;
      else return this[p] = t, i?.(), true;
      else try {
        new F(t.subarray(0, 512)), this.brotli = false;
      } catch {
        this.brotli = true;
      }
      if (this[w] === void 0 || this[w] === false && (this.brotli || o)) {
        let a = this[ut];
        this[ut] = false, this[w] = this[w] === void 0 ? new Ue({}) : o ? new Ke({}) : new Ge({}), this[w].on("data", (c) => {
          this[Xs](c) && this[Xe](c);
        }), this[w].on("error", (c) => {
          this[$] || this.abort(c);
        }), this[w].on("end", () => {
          this[ut] = true, this[Xe]();
        }), this[Yt] = true, this[le] += t.length;
        let l = !!this[w][a ? "end" : "write"](t);
        return this[Yt] = false, i?.(), l;
      }
    }
    this[Yt] = true, this[w] ? (this[le] += t.length, this[w].write(t)) : this[Xe](t), this[Yt] = false;
    let n = this[st].length > 0 ? false : this[it] ? this[it].flowing : true;
    return !n && this[st].length === 0 && this[it]?.once("drain", () => this.emit("drain")), i?.(), n;
  }
  [Vi](t) {
    t && !this[$] && (this[p] = this[p] ? Buffer.concat([this[p], t]) : t);
  }
  [Qe]() {
    if (this[ut] && !this[Yi] && !this[$] && !this[ae]) {
      this[Yi] = true;
      let t = this[Nt];
      if (t?.blockRemain) {
        let e = this[p] ? this[p].length : 0;
        this.warn("TAR_BAD_ARCHIVE", `Truncated input (needed ${t.blockRemain} more bytes, only ${e} available)`, { entry: t }), this[p] && t.write(this[p]), t.end();
      }
      this[At](Je);
    }
  }
  [Xe](t) {
    if (this[ae] && t) this[Vi](t);
    else if (!t && !this[p]) this[Qe]();
    else if (t) {
      if (this[ae] = true, this[p]) {
        this[Vi](t);
        let e = this[p];
        this[p] = void 0, this[qe](e);
      } else this[qe](t);
      for (; this[p] && this[p]?.length >= 512 && !this[$] && !this[ti]; ) {
        let e = this[p];
        this[p] = void 0, this[qe](e);
      }
      this[ae] = false;
    }
    (!this[p] || this[ut]) && this[Qe]();
  }
  [qe](t) {
    let e = 0, i = t.length;
    for (; e + 512 <= i && !this[$] && !this[ti]; ) switch (this[B]) {
      case "begin":
      case "header":
        this[Vs](t, e), e += 512;
        break;
      case "ignore":
      case "body":
        e += this[Ki](t, e);
        break;
      case "meta":
        e += this[Ks](t, e);
        break;
      default:
        throw new Error("invalid state: " + this[B]);
    }
    e < i && (this[p] = this[p] ? Buffer.concat([t.subarray(e), this[p]]) : t.subarray(e));
  }
  end(t, e, i) {
    return typeof t == "function" && (i = t, e = void 0, t = void 0), typeof e == "function" && (i = e, e = void 0), typeof t == "string" && (t = Buffer.from(t, e)), i && this.once("finish", i), this[$] || (this[w] ? (t && (this[le] += t.length, this[w].write(t)), this[w].end()) : (this[ut] = true, (this.brotli === void 0 || this.zstd === void 0) && (t = t || Buffer.alloc(0)), t && this.write(t), this[Qe]())), this;
  }
};
var mt = (s3) => {
  let t = s3.length - 1, e = -1;
  for (; t > -1 && s3.charAt(t) === "/"; ) e = t, t--;
  return e === -1 ? s3 : s3.slice(0, e);
};
var vn = (s3) => {
  let t = s3.onReadEntry;
  s3.onReadEntry = t ? (e) => {
    t(e), e.resume();
  } : (e) => e.resume();
};
var Qi = (s3, t) => {
  let e = new Map(t.map((o) => [mt(o), true])), i = s3.filter, r = 100, n = (o, h = "", a = 0) => {
    if (a >= r) return e.set(o, false), false;
    let l = h || kn(o).root || ".", c;
    if (o === l) c = false;
    else {
      let d = e.get(o);
      c = d !== void 0 ? d : n(Fn(o), l, a + 1);
    }
    return e.set(o, c), c;
  };
  s3.filter = i ? (o, h) => i(o, h) && n(mt(o)) : (o) => n(mt(o));
};
var Mn = (s3) => {
  let t = new rt(s3), e = s3.file, i;
  try {
    i = Kt.openSync(e, "r");
    let r = Kt.fstatSync(i), n = s3.maxReadSize || 16 * 1024 * 1024;
    if (r.size < n) {
      let o = Buffer.allocUnsafe(r.size), h = Kt.readSync(i, o, 0, r.size, 0);
      t.end(h === o.byteLength ? o : o.subarray(0, h));
    } else {
      let o = 0, h = Buffer.allocUnsafe(n);
      for (; o < r.size; ) {
        let a = Kt.readSync(i, h, 0, n, o);
        if (a === 0) break;
        o += a, t.write(h.subarray(0, a));
      }
      t.end();
    }
  } finally {
    if (typeof i == "number") try {
      Kt.closeSync(i);
    } catch {
    }
  }
};
var Bn = (s3, t) => {
  let e = new rt(s3), i = s3.maxReadSize || 16 * 1024 * 1024, r = s3.file;
  return new Promise((o, h) => {
    e.on("error", h), e.on("end", o), Kt.stat(r, (a, l) => {
      if (a) h(a);
      else {
        let c = new _t(r, { readSize: i, size: l.size });
        c.on("error", h), c.pipe(e);
      }
    });
  });
};
var Ct = K(Mn, Bn, (s3) => new rt(s3), (s3) => new rt(s3), (s3, t) => {
  t?.length && Qi(s3, t), s3.noResume || vn(s3);
});
var Ji = (s3, t, e) => (s3 &= 4095, e && (s3 = (s3 | 384) & -19), t && (s3 & 256 && (s3 |= 64), s3 & 32 && (s3 |= 8), s3 & 4 && (s3 |= 1)), s3);
var { isAbsolute: zn, parse: qs } = Pn;
var ce = (s3) => {
  let t = "", e = qs(s3);
  for (; zn(s3) || e.root; ) {
    let i = s3.charAt(0) === "/" && s3.slice(0, 4) !== "//?/" ? "/" : e.root;
    s3 = s3.slice(i.length), t += i, e = qs(s3);
  }
  return [t, s3];
};
var ei = ["|", "<", ">", "?", ":"];
var ji = ei.map((s3) => String.fromCodePoint(61440 + Number(s3.codePointAt(0))));
var Un = new Map(ei.map((s3, t) => [s3, ji[t]]));
var Hn = new Map(ji.map((s3, t) => [s3, ei[t]]));
var ts = (s3) => ei.reduce((t, e) => t.split(e).join(Un.get(e)), s3);
var Qs = (s3) => ji.reduce((t, e) => t.split(e).join(Hn.get(e)), s3);
var rr = (s3, t) => t ? (s3 = f(s3).replace(/^\.(\/|$)/, ""), mt(t) + "/" + s3) : f(s3);
var Wn = 16 * 1024 * 1024;
var tr = /* @__PURE__ */ Symbol("process");
var er = /* @__PURE__ */ Symbol("file");
var ir = /* @__PURE__ */ Symbol("directory");
var is = /* @__PURE__ */ Symbol("symlink");
var sr = /* @__PURE__ */ Symbol("hardlink");
var fe = /* @__PURE__ */ Symbol("header");
var ii = /* @__PURE__ */ Symbol("read");
var ss = /* @__PURE__ */ Symbol("lstat");
var si = /* @__PURE__ */ Symbol("onlstat");
var rs = /* @__PURE__ */ Symbol("onread");
var ns = /* @__PURE__ */ Symbol("onreadlink");
var os = /* @__PURE__ */ Symbol("openfile");
var hs = /* @__PURE__ */ Symbol("onopenfile");
var pt = /* @__PURE__ */ Symbol("close");
var ri = /* @__PURE__ */ Symbol("mode");
var as = /* @__PURE__ */ Symbol("awaitDrain");
var es = /* @__PURE__ */ Symbol("ondrain");
var q = /* @__PURE__ */ Symbol("prefix");
var de = class extends A {
  path;
  portable;
  myuid = process.getuid && process.getuid() || 0;
  myuser = process.env.USER || "";
  maxReadSize;
  linkCache;
  statCache;
  preservePaths;
  cwd;
  strict;
  mtime;
  noPax;
  noMtime;
  prefix;
  fd;
  blockLen = 0;
  blockRemain = 0;
  buf;
  pos = 0;
  remain = 0;
  length = 0;
  offset = 0;
  win32;
  absolute;
  header;
  type;
  linkpath;
  stat;
  onWriteEntry;
  #t = false;
  constructor(t, e = {}) {
    let i = se(e);
    super(), this.path = f(t), this.portable = !!i.portable, this.maxReadSize = i.maxReadSize || Wn, this.linkCache = i.linkCache || /* @__PURE__ */ new Map(), this.statCache = i.statCache || /* @__PURE__ */ new Map(), this.preservePaths = !!i.preservePaths, this.cwd = f(i.cwd || process.cwd()), this.strict = !!i.strict, this.noPax = !!i.noPax, this.noMtime = !!i.noMtime, this.mtime = i.mtime, this.prefix = i.prefix ? f(i.prefix) : void 0, this.onWriteEntry = i.onWriteEntry, typeof i.onwarn == "function" && this.on("warn", i.onwarn);
    let r = false;
    if (!this.preservePaths) {
      let [o, h] = ce(this.path);
      o && typeof h == "string" && (this.path = h, r = o);
    }
    this.win32 = !!i.win32 || process.platform === "win32", this.win32 && (this.path = Qs(this.path.replaceAll(/\\/g, "/")), t = t.replaceAll(/\\/g, "/")), this.absolute = f(i.absolute || js.resolve(this.cwd, t)), this.path === "" && (this.path = "./"), r && this.warn("TAR_ENTRY_INFO", `stripping ${r} from absolute path`, { entry: this, path: r + this.path });
    let n = this.statCache.get(this.absolute);
    n ? this[si](n) : this[ss]();
  }
  warn(t, e, i = {}) {
    return Dt(this, t, e, i);
  }
  emit(t, ...e) {
    return t === "error" && (this.#t = true), super.emit(t, ...e);
  }
  [ss]() {
    X.lstat(this.absolute, (t, e) => {
      if (t) return this.emit("error", t);
      this[si](e);
    });
  }
  [si](t) {
    this.statCache.set(this.absolute, t), this.stat = t, t.isFile() || (t.size = 0), this.type = Gn(t), this.emit("stat", t), this[tr]();
  }
  [tr]() {
    switch (this.type) {
      case "File":
        return this[er]();
      case "Directory":
        return this[ir]();
      case "SymbolicLink":
        return this[is]();
      default:
        return this.end();
    }
  }
  [ri](t) {
    return Ji(t, this.type === "Directory", this.portable);
  }
  [q](t) {
    return rr(t, this.prefix);
  }
  [fe]() {
    if (!this.stat) throw new Error("cannot write header before stat");
    this.type === "Directory" && this.portable && (this.noMtime = true), this.onWriteEntry?.(this), this.header = new F({ path: this[q](this.path), linkpath: this.type === "Link" && this.linkpath !== void 0 ? this[q](this.linkpath) : this.linkpath, mode: this[ri](this.stat.mode), uid: this.portable ? void 0 : this.stat.uid, gid: this.portable ? void 0 : this.stat.gid, size: this.stat.size, mtime: this.noMtime ? void 0 : this.mtime || this.stat.mtime, type: this.type === "Unsupported" ? void 0 : this.type, uname: this.portable ? void 0 : this.stat.uid === this.myuid ? this.myuser : "", atime: this.portable ? void 0 : this.stat.atime, ctime: this.portable ? void 0 : this.stat.ctime }), this.header.encode() && !this.noPax && super.write(new ft({ atime: this.portable ? void 0 : this.header.atime, ctime: this.portable ? void 0 : this.header.ctime, gid: this.portable ? void 0 : this.header.gid, mtime: this.noMtime ? void 0 : this.mtime || this.header.mtime, path: this[q](this.path), linkpath: this.type === "Link" && this.linkpath !== void 0 ? this[q](this.linkpath) : this.linkpath, size: this.header.size, uid: this.portable ? void 0 : this.header.uid, uname: this.portable ? void 0 : this.header.uname, dev: this.portable ? void 0 : this.stat.dev, ino: this.portable ? void 0 : this.stat.ino, nlink: this.portable ? void 0 : this.stat.nlink }).encode());
    let t = this.header?.block;
    if (!t) throw new Error("failed to encode header");
    super.write(t);
  }
  [ir]() {
    if (!this.stat) throw new Error("cannot create directory entry without stat");
    this.path.slice(-1) !== "/" && (this.path += "/"), this.stat.size = 0, this[fe](), this.end();
  }
  [is]() {
    X.readlink(this.absolute, (t, e) => {
      if (t) return this.emit("error", t);
      this[ns](e);
    });
  }
  [ns](t) {
    this.linkpath = f(t), this[fe](), this.end();
  }
  [sr](t) {
    if (!this.stat) throw new Error("cannot create link entry without stat");
    this.type = "Link", this.linkpath = f(js.relative(this.cwd, t)), this.stat.size = 0, this[fe](), this.end();
  }
  [er]() {
    if (!this.stat) throw new Error("cannot create file entry without stat");
    if (this.stat.nlink > 1) {
      let t = `${this.stat.dev}:${this.stat.ino}`, e = this.linkCache.get(t);
      if (e?.indexOf(this.cwd) === 0) return this[sr](e);
      this.linkCache.set(t, this.absolute);
    }
    if (this[fe](), this.stat.size === 0) return this.end();
    this[os]();
  }
  [os]() {
    X.open(this.absolute, "r", (t, e) => {
      if (t) return this.emit("error", t);
      this[hs](e);
    });
  }
  [hs](t) {
    if (this.fd = t, this.#t) return this[pt]();
    if (!this.stat) throw new Error("should stat before calling onopenfile");
    this.blockLen = 512 * Math.ceil(this.stat.size / 512), this.blockRemain = this.blockLen;
    let e = Math.min(this.blockLen, this.maxReadSize);
    this.buf = Buffer.allocUnsafe(e), this.offset = 0, this.pos = 0, this.remain = this.stat.size, this.length = this.buf.length, this[ii]();
  }
  [ii]() {
    let { fd: t, buf: e, offset: i, length: r, pos: n } = this;
    if (t === void 0 || e === void 0) throw new Error("cannot read file without first opening");
    X.read(t, e, i, r, n, (o, h) => {
      if (o) return this[pt](() => this.emit("error", o));
      this[rs](h);
    });
  }
  [pt](t = () => {
  }) {
    this.fd !== void 0 && X.close(this.fd, t);
  }
  [rs](t) {
    if (t <= 0 && this.remain > 0) {
      let r = Object.assign(new Error("encountered unexpected EOF"), { path: this.absolute, syscall: "read", code: "EOF" });
      return this[pt](() => this.emit("error", r));
    }
    if (t > this.remain) {
      let r = Object.assign(new Error("did not encounter expected EOF"), { path: this.absolute, syscall: "read", code: "EOF" });
      return this[pt](() => this.emit("error", r));
    }
    if (!this.buf) throw new Error("should have created buffer prior to reading");
    if (t === this.remain) for (let r = t; r < this.length && t < this.blockRemain; r++) this.buf[r + this.offset] = 0, t++, this.remain++;
    let e = this.offset === 0 && t === this.buf.length ? this.buf : this.buf.subarray(this.offset, this.offset + t);
    this.write(e) ? this[es]() : this[as](() => this[es]());
  }
  [as](t) {
    this.once("drain", t);
  }
  write(t, e, i) {
    if (typeof e == "function" && (i = e, e = void 0), typeof t == "string" && (t = Buffer.from(t, typeof e == "string" ? e : "utf8")), this.blockRemain < t.length) {
      let r = Object.assign(new Error("writing more data than expected"), { path: this.absolute });
      return this.emit("error", r);
    }
    return this.remain -= t.length, this.blockRemain -= t.length, this.pos += t.length, this.offset += t.length, super.write(t, null, i);
  }
  [es]() {
    if (!this.remain) return this.blockRemain && super.write(Buffer.alloc(this.blockRemain)), this[pt]((t) => t ? this.emit("error", t) : this.end());
    if (!this.buf) throw new Error("buffer lost somehow in ONDRAIN");
    this.offset >= this.length && (this.buf = Buffer.allocUnsafe(Math.min(this.blockRemain, this.buf.length)), this.offset = 0), this.length = this.buf.length - this.offset, this[ii]();
  }
};
var ni = class extends de {
  sync = true;
  [ss]() {
    this[si](X.lstatSync(this.absolute));
  }
  [is]() {
    this[ns](X.readlinkSync(this.absolute));
  }
  [os]() {
    this[hs](X.openSync(this.absolute, "r"));
  }
  [ii]() {
    let t = true;
    try {
      let { fd: e, buf: i, offset: r, length: n, pos: o } = this;
      if (e === void 0 || i === void 0) throw new Error("fd and buf must be set in READ method");
      let h = X.readSync(e, i, r, n, o);
      this[rs](h), t = false;
    } finally {
      if (t) try {
        this[pt](() => {
        });
      } catch {
      }
    }
  }
  [as](t) {
    t();
  }
  [pt](t = () => {
  }) {
    this.fd !== void 0 && X.closeSync(this.fd), t();
  }
};
var oi = class extends A {
  blockLen = 0;
  blockRemain = 0;
  buf = 0;
  pos = 0;
  remain = 0;
  length = 0;
  preservePaths;
  portable;
  strict;
  noPax;
  noMtime;
  readEntry;
  type;
  prefix;
  path;
  mode;
  uid;
  gid;
  uname;
  gname;
  header;
  mtime;
  atime;
  ctime;
  linkpath;
  size;
  onWriteEntry;
  warn(t, e, i = {}) {
    return Dt(this, t, e, i);
  }
  constructor(t, e = {}) {
    let i = se(e);
    super(), this.preservePaths = !!i.preservePaths, this.portable = !!i.portable, this.strict = !!i.strict, this.noPax = !!i.noPax, this.noMtime = !!i.noMtime, this.onWriteEntry = i.onWriteEntry, this.readEntry = t;
    let { type: r } = t;
    if (r === "Unsupported") throw new Error("writing entry that should be ignored");
    this.type = r, this.type === "Directory" && this.portable && (this.noMtime = true), this.prefix = i.prefix, this.path = f(t.path), this.mode = t.mode !== void 0 ? this[ri](t.mode) : void 0, this.uid = this.portable ? void 0 : t.uid, this.gid = this.portable ? void 0 : t.gid, this.uname = this.portable ? void 0 : t.uname, this.gname = this.portable ? void 0 : t.gname, this.size = t.size, this.mtime = this.noMtime ? void 0 : i.mtime || t.mtime, this.atime = this.portable ? void 0 : t.atime, this.ctime = this.portable ? void 0 : t.ctime, this.linkpath = t.linkpath !== void 0 ? f(t.linkpath) : void 0, typeof i.onwarn == "function" && this.on("warn", i.onwarn);
    let n = false;
    if (!this.preservePaths) {
      let [h, a] = ce(this.path);
      h && typeof a == "string" && (this.path = a, n = h);
    }
    this.remain = t.size, this.blockRemain = t.startBlockSize, this.onWriteEntry?.(this), this.header = new F({ path: this[q](this.path), linkpath: this.type === "Link" && this.linkpath !== void 0 ? this[q](this.linkpath) : this.linkpath, mode: this.mode, uid: this.portable ? void 0 : this.uid, gid: this.portable ? void 0 : this.gid, size: this.size, mtime: this.noMtime ? void 0 : this.mtime, type: this.type, uname: this.portable ? void 0 : this.uname, atime: this.portable ? void 0 : this.atime, ctime: this.portable ? void 0 : this.ctime }), n && this.warn("TAR_ENTRY_INFO", `stripping ${n} from absolute path`, { entry: this, path: n + this.path }), this.header.encode() && !this.noPax && super.write(new ft({ atime: this.portable ? void 0 : this.atime, ctime: this.portable ? void 0 : this.ctime, gid: this.portable ? void 0 : this.gid, mtime: this.noMtime ? void 0 : this.mtime, path: this[q](this.path), linkpath: this.type === "Link" && this.linkpath !== void 0 ? this[q](this.linkpath) : this.linkpath, size: this.size, uid: this.portable ? void 0 : this.uid, uname: this.portable ? void 0 : this.uname, dev: this.portable ? void 0 : this.readEntry.dev, ino: this.portable ? void 0 : this.readEntry.ino, nlink: this.portable ? void 0 : this.readEntry.nlink }).encode());
    let o = this.header?.block;
    if (!o) throw new Error("failed to encode header");
    super.write(o), t.pipe(this);
  }
  [q](t) {
    return rr(t, this.prefix);
  }
  [ri](t) {
    return Ji(t, this.type === "Directory", this.portable);
  }
  write(t, e, i) {
    typeof e == "function" && (i = e, e = void 0), typeof t == "string" && (t = Buffer.from(t, typeof e == "string" ? e : "utf8"));
    let r = t.length;
    if (r > this.blockRemain) throw new Error("writing more to entry than is appropriate");
    return this.blockRemain -= r, super.write(t, i);
  }
  end(t, e, i) {
    return this.blockRemain && super.write(Buffer.alloc(this.blockRemain)), typeof t == "function" && (i = t, e = void 0, t = void 0), typeof e == "function" && (i = e, e = void 0), typeof t == "string" && (t = Buffer.from(t, e ?? "utf8")), i && this.once("finish", i), t ? super.end(t, i) : super.end(i), this;
  }
};
var Gn = (s3) => s3.isFile() ? "File" : s3.isDirectory() ? "Directory" : s3.isSymbolicLink() ? "SymbolicLink" : "Unsupported";
var hi = class s2 {
  tail;
  head;
  length = 0;
  static create(t = []) {
    return new s2(t);
  }
  constructor(t = []) {
    for (let e of t) this.push(e);
  }
  *[Symbol.iterator]() {
    for (let t = this.head; t; t = t.next) yield t.value;
  }
  removeNode(t) {
    if (t.list !== this) throw new Error("removing node which does not belong to this list");
    let e = t.next, i = t.prev;
    return e && (e.prev = i), i && (i.next = e), t === this.head && (this.head = e), t === this.tail && (this.tail = i), this.length--, t.next = void 0, t.prev = void 0, t.list = void 0, e;
  }
  unshiftNode(t) {
    if (t === this.head) return;
    t.list && t.list.removeNode(t);
    let e = this.head;
    t.list = this, t.next = e, e && (e.prev = t), this.head = t, this.tail || (this.tail = t), this.length++;
  }
  pushNode(t) {
    if (t === this.tail) return;
    t.list && t.list.removeNode(t);
    let e = this.tail;
    t.list = this, t.prev = e, e && (e.next = t), this.tail = t, this.head || (this.head = t), this.length++;
  }
  push(...t) {
    for (let e = 0, i = t.length; e < i; e++) Yn(this, t[e]);
    return this.length;
  }
  unshift(...t) {
    for (var e = 0, i = t.length; e < i; e++) Kn(this, t[e]);
    return this.length;
  }
  pop() {
    if (!this.tail) return;
    let t = this.tail.value, e = this.tail;
    return this.tail = this.tail.prev, this.tail ? this.tail.next = void 0 : this.head = void 0, e.list = void 0, this.length--, t;
  }
  shift() {
    if (!this.head) return;
    let t = this.head.value, e = this.head;
    return this.head = this.head.next, this.head ? this.head.prev = void 0 : this.tail = void 0, e.list = void 0, this.length--, t;
  }
  forEach(t, e) {
    e = e || this;
    for (let i = this.head, r = 0; i; r++) t.call(e, i.value, r, this), i = i.next;
  }
  forEachReverse(t, e) {
    e = e || this;
    for (let i = this.tail, r = this.length - 1; i; r--) t.call(e, i.value, r, this), i = i.prev;
  }
  get(t) {
    let e = 0, i = this.head;
    for (; i && e < t; e++) i = i.next;
    if (e === t && i) return i.value;
  }
  getReverse(t) {
    let e = 0, i = this.tail;
    for (; i && e < t; e++) i = i.prev;
    if (e === t && i) return i.value;
  }
  map(t, e) {
    e = e || this;
    let i = new s2();
    for (let r = this.head; r; ) i.push(t.call(e, r.value, this)), r = r.next;
    return i;
  }
  mapReverse(t, e) {
    e = e || this;
    var i = new s2();
    for (let r = this.tail; r; ) i.push(t.call(e, r.value, this)), r = r.prev;
    return i;
  }
  reduce(t, e) {
    let i, r = this.head;
    if (arguments.length > 1) i = e;
    else if (this.head) r = this.head.next, i = this.head.value;
    else throw new TypeError("Reduce of empty list with no initial value");
    for (var n = 0; r; n++) i = t(i, r.value, n), r = r.next;
    return i;
  }
  reduceReverse(t, e) {
    let i, r = this.tail;
    if (arguments.length > 1) i = e;
    else if (this.tail) r = this.tail.prev, i = this.tail.value;
    else throw new TypeError("Reduce of empty list with no initial value");
    for (let n = this.length - 1; r; n--) i = t(i, r.value, n), r = r.prev;
    return i;
  }
  toArray() {
    let t = new Array(this.length);
    for (let e = 0, i = this.head; i; e++) t[e] = i.value, i = i.next;
    return t;
  }
  toArrayReverse() {
    let t = new Array(this.length);
    for (let e = 0, i = this.tail; i; e++) t[e] = i.value, i = i.prev;
    return t;
  }
  slice(t = 0, e = this.length) {
    e < 0 && (e += this.length), t < 0 && (t += this.length);
    let i = new s2();
    if (e < t || e < 0) return i;
    t < 0 && (t = 0), e > this.length && (e = this.length);
    let r = this.head, n = 0;
    for (n = 0; r && n < t; n++) r = r.next;
    for (; r && n < e; n++, r = r.next) i.push(r.value);
    return i;
  }
  sliceReverse(t = 0, e = this.length) {
    e < 0 && (e += this.length), t < 0 && (t += this.length);
    let i = new s2();
    if (e < t || e < 0) return i;
    t < 0 && (t = 0), e > this.length && (e = this.length);
    let r = this.length, n = this.tail;
    for (; n && r > e; r--) n = n.prev;
    for (; n && r > t; r--, n = n.prev) i.push(n.value);
    return i;
  }
  splice(t, e = 0, ...i) {
    t > this.length && (t = this.length - 1), t < 0 && (t = this.length + t);
    let r = this.head;
    for (let o = 0; r && o < t; o++) r = r.next;
    let n = [];
    for (let o = 0; r && o < e; o++) n.push(r.value), r = this.removeNode(r);
    r ? r !== this.tail && (r = r.prev) : r = this.tail;
    for (let o of i) r = Zn(this, r, o);
    return n;
  }
  reverse() {
    let t = this.head, e = this.tail;
    for (let i = t; i; i = i.prev) {
      let r = i.prev;
      i.prev = i.next, i.next = r;
    }
    return this.head = e, this.tail = t, this;
  }
};
function Zn(s3, t, e) {
  let i = t, r = t ? t.next : s3.head, n = new ue(e, i, r, s3);
  return n.next === void 0 && (s3.tail = n), n.prev === void 0 && (s3.head = n), s3.length++, n;
}
function Yn(s3, t) {
  s3.tail = new ue(t, s3.tail, void 0, s3), s3.head || (s3.head = s3.tail), s3.length++;
}
function Kn(s3, t) {
  s3.head = new ue(t, void 0, s3.head, s3), s3.tail || (s3.tail = s3.head), s3.length++;
}
var ue = class {
  list;
  next;
  prev;
  value;
  constructor(t, e, i, r) {
    this.list = r, this.value = t, e ? (e.next = this, this.prev = e) : this.prev = void 0, i ? (i.prev = this, this.next = i) : this.next = void 0;
  }
};
var pi = class {
  path;
  absolute;
  entry;
  stat;
  readdir;
  pending = false;
  pendingLink = false;
  ignore = false;
  piped = false;
  constructor(t, e) {
    this.path = t || "./", this.absolute = e;
  }
};
var nr = Buffer.alloc(1024);
var li = /* @__PURE__ */ Symbol("onStat");
var me = /* @__PURE__ */ Symbol("ended");
var W = /* @__PURE__ */ Symbol("queue");
var pe = /* @__PURE__ */ Symbol("pendingLinks");
var Et = /* @__PURE__ */ Symbol("current");
var Ft = /* @__PURE__ */ Symbol("process");
var Ee = /* @__PURE__ */ Symbol("processing");
var ai = /* @__PURE__ */ Symbol("processJob");
var G = /* @__PURE__ */ Symbol("jobs");
var ls = /* @__PURE__ */ Symbol("jobDone");
var ci = /* @__PURE__ */ Symbol("addFSEntry");
var or = /* @__PURE__ */ Symbol("addTarEntry");
var ds = /* @__PURE__ */ Symbol("stat");
var us = /* @__PURE__ */ Symbol("readdir");
var fi = /* @__PURE__ */ Symbol("onreaddir");
var di = /* @__PURE__ */ Symbol("pipe");
var hr = /* @__PURE__ */ Symbol("entry");
var cs = /* @__PURE__ */ Symbol("entryOpt");
var ui = /* @__PURE__ */ Symbol("writeEntryClass");
var lr = /* @__PURE__ */ Symbol("write");
var fs = /* @__PURE__ */ Symbol("ondrain");
var wt = class extends A {
  sync = false;
  opt;
  cwd;
  maxReadSize;
  preservePaths;
  strict;
  noPax;
  prefix;
  linkCache;
  statCache;
  file;
  portable;
  zip;
  readdirCache;
  noDirRecurse;
  follow;
  noMtime;
  mtime;
  filter;
  jobs;
  [ui];
  onWriteEntry;
  [W];
  [pe] = /* @__PURE__ */ new Map();
  [G] = 0;
  [Ee] = false;
  [me] = false;
  constructor(t = {}) {
    if (super(), this.opt = t, this.file = t.file || "", this.cwd = t.cwd || process.cwd(), this.maxReadSize = t.maxReadSize, this.preservePaths = !!t.preservePaths, this.strict = !!t.strict, this.noPax = !!t.noPax, this.prefix = f(t.prefix || ""), this.linkCache = t.linkCache || /* @__PURE__ */ new Map(), this.statCache = t.statCache || /* @__PURE__ */ new Map(), this.readdirCache = t.readdirCache || /* @__PURE__ */ new Map(), this.onWriteEntry = t.onWriteEntry, this[ui] = de, typeof t.onwarn == "function" && this.on("warn", t.onwarn), this.portable = !!t.portable, t.gzip || t.brotli || t.zstd) {
      if ((t.gzip ? 1 : 0) + (t.brotli ? 1 : 0) + (t.zstd ? 1 : 0) > 1) throw new TypeError("gzip, brotli, zstd are mutually exclusive");
      if (t.gzip && (typeof t.gzip != "object" && (t.gzip = {}), this.portable && (t.gzip.portable = true), this.zip = new ze(t.gzip)), t.brotli && (typeof t.brotli != "object" && (t.brotli = {}), this.zip = new We(t.brotli)), t.zstd && (typeof t.zstd != "object" && (t.zstd = {}), this.zip = new Ye(t.zstd)), !this.zip) throw new Error("impossible");
      let e = this.zip;
      e.on("data", (i) => super.write(i)), e.on("end", () => super.end()), e.on("drain", () => this[fs]()), this.on("resume", () => e.resume());
    } else this.on("drain", this[fs]);
    this.noDirRecurse = !!t.noDirRecurse, this.follow = !!t.follow, this.noMtime = !!t.noMtime, t.mtime && (this.mtime = t.mtime), this.filter = typeof t.filter == "function" ? t.filter : () => true, this[W] = new hi(), this[G] = 0, this.jobs = Number(t.jobs) || 4, this[Ee] = false, this[me] = false;
  }
  [lr](t) {
    return super.write(t);
  }
  add(t) {
    return this.write(t), this;
  }
  end(t, e, i) {
    return typeof t == "function" && (i = t, t = void 0), typeof e == "function" && (i = e, e = void 0), t && this.add(t), this[me] = true, this[Ft](), i && i(), this;
  }
  write(t) {
    if (this[me]) throw new Error("write after end");
    return typeof t == "string" ? this[ci](t) : this[or](t), this.flowing;
  }
  [or](t) {
    let e = f(ar.resolve(this.cwd, t.path));
    if (!this.filter(t.path, t)) t.resume();
    else {
      let i = new pi(t.path, e);
      i.entry = new oi(t, this[cs](i)), i.entry.on("end", () => this[ls](i)), this[G] += 1, this[W].push(i);
    }
    this[Ft]();
  }
  [ci](t) {
    let e = f(ar.resolve(this.cwd, t));
    this[W].push(new pi(t, e)), this[Ft]();
  }
  [ds](t) {
    t.pending = true, this[G] += 1;
    let e = this.follow ? "stat" : "lstat";
    mi[e](t.absolute, (i, r) => {
      t.pending = false, this[G] -= 1, i ? this.emit("error", i) : this[li](t, r);
    });
  }
  [li](t, e) {
    if (this.statCache.set(t.absolute, e), t.stat = e, !this.filter(t.path, e)) t.ignore = true;
    else if (e.isFile() && e.nlink > 1 && !this.linkCache.get(`${e.dev}:${e.ino}`) && !this.sync) if (t === this[Et]) this[ai](t);
    else {
      let i = `${e.dev}:${e.ino}`, r = this[pe].get(i);
      r ? r.push(t) : this[pe].set(i, [t]), t.pendingLink = true, t.pending = true;
    }
    this[Ft]();
  }
  [us](t) {
    t.pending = true, this[G] += 1, mi.readdir(t.absolute, (e, i) => {
      if (t.pending = false, this[G] -= 1, e) return this.emit("error", e);
      this[fi](t, i);
    });
  }
  [fi](t, e) {
    this.readdirCache.set(t.absolute, e), t.readdir = e, this[Ft]();
  }
  [Ft]() {
    if (!this[Ee]) {
      this[Ee] = true;
      for (let t = this[W].head; t && this[G] < this.jobs; t = t.next) if (this[ai](t.value), t.value.ignore) {
        let e = t.next;
        this[W].removeNode(t), t.next = e;
      }
      this[Ee] = false, this[me] && this[W].length === 0 && this[G] === 0 && (this.zip ? this.zip.end(nr) : (super.write(nr), super.end()));
    }
  }
  get [Et]() {
    return this[W] && this[W].head && this[W].head.value;
  }
  [ls](t) {
    this[W].shift(), this[G] -= 1;
    let { stat: e } = t;
    if (e && e.isFile() && e.nlink > 1) {
      let i = `${e.dev}:${e.ino}`, r = this[pe].get(i);
      if (r) {
        this[pe].delete(i);
        for (let n of r) n.pending = false, this[ai](n);
      }
    }
    this[Ft]();
  }
  [ai](t) {
    if (t.pending && t.pendingLink && t === this[Et] && (t.pending = false, t.pendingLink = false), !t.pending) {
      if (t.entry) {
        t === this[Et] && !t.piped && this[di](t);
        return;
      }
      if (!t.stat) {
        let e = this.statCache.get(t.absolute);
        e ? this[li](t, e) : this[ds](t);
      }
      if (t.stat && !t.ignore) {
        if (!this.noDirRecurse && t.stat.isDirectory() && !t.readdir) {
          let e = this.readdirCache.get(t.absolute);
          if (e ? this[fi](t, e) : this[us](t), !t.readdir) return;
        }
        if (t.entry = this[hr](t), !t.entry) {
          t.ignore = true;
          return;
        }
        t === this[Et] && !t.piped && this[di](t);
      }
    }
  }
  [cs](t) {
    return { onwarn: (e, i, r) => this.warn(e, i, r), noPax: this.noPax, cwd: this.cwd, absolute: t.absolute, preservePaths: this.preservePaths, maxReadSize: this.maxReadSize, strict: this.strict, portable: this.portable, linkCache: this.linkCache, statCache: this.statCache, noMtime: this.noMtime, mtime: this.mtime, prefix: this.prefix, onWriteEntry: this.onWriteEntry };
  }
  [hr](t) {
    this[G] += 1;
    try {
      return new this[ui](t.path, this[cs](t)).on("end", () => this[ls](t)).on("error", (i) => this.emit("error", i));
    } catch (e) {
      this.emit("error", e);
    }
  }
  [fs]() {
    this[Et] && this[Et].entry && this[Et].entry.resume();
  }
  [di](t) {
    t.piped = true, t.readdir && t.readdir.forEach((r) => {
      let n = t.path, o = n === "./" ? "" : n.replace(/\/*$/, "/");
      this[ci](o + r);
    });
    let e = t.entry, i = this.zip;
    if (!e) throw new Error("cannot pipe without source");
    i ? e.on("data", (r) => {
      i.write(r) || e.pause();
    }) : e.on("data", (r) => {
      super.write(r) || e.pause();
    });
  }
  pause() {
    return this.zip && this.zip.pause(), super.pause();
  }
  warn(t, e, i = {}) {
    Dt(this, t, e, i);
  }
};
var kt = class extends wt {
  sync = true;
  constructor(t) {
    super(t), this[ui] = ni;
  }
  pause() {
  }
  resume() {
  }
  [ds](t) {
    let e = this.follow ? "statSync" : "lstatSync";
    this[li](t, mi[e](t.absolute));
  }
  [us](t) {
    this[fi](t, mi.readdirSync(t.absolute));
  }
  [di](t) {
    let e = t.entry, i = this.zip;
    if (t.readdir && t.readdir.forEach((r) => {
      let n = t.path, o = n === "./" ? "" : n.replace(/\/*$/, "/");
      this[ci](o + r);
    }), !e) throw new Error("Cannot pipe without source");
    i ? e.on("data", (r) => {
      i.write(r);
    }) : e.on("data", (r) => {
      super[lr](r);
    });
  }
};
var Vn = (s3, t) => {
  let e = new kt(s3), i = new Wt(s3.file, { mode: s3.mode || 438 });
  e.pipe(i), fr(e, t);
};
var $n = (s3, t) => {
  let e = new wt(s3), i = new et(s3.file, { mode: s3.mode || 438 });
  e.pipe(i);
  let r = new Promise((n, o) => {
    i.on("error", o), i.on("close", n), e.on("error", o);
  });
  return dr(e, t).catch((n) => e.emit("error", n)), r;
};
var fr = (s3, t) => {
  t.forEach((e) => {
    e.charAt(0) === "@" ? Ct({ file: cr.resolve(s3.cwd, e.slice(1)), sync: true, noResume: true, onReadEntry: (i) => s3.add(i) }) : s3.add(e);
  }), s3.end();
};
var dr = async (s3, t) => {
  for (let e of t) e.charAt(0) === "@" ? await Ct({ file: cr.resolve(String(s3.cwd), e.slice(1)), noResume: true, onReadEntry: (i) => {
    s3.add(i);
  } }) : s3.add(e);
  s3.end();
};
var Xn = (s3, t) => {
  let e = new kt(s3);
  return fr(e, t), e;
};
var qn = (s3, t) => {
  let e = new wt(s3);
  return dr(e, t).catch((i) => e.emit("error", i)), e;
};
var Qn = K(Vn, $n, Xn, qn, (s3, t) => {
  if (!t?.length) throw new TypeError("no paths specified to add to archive");
});
var Jn = process.env.__FAKE_PLATFORM__ || process.platform;
var Er = Jn === "win32";
var { O_CREAT: wr, O_NOFOLLOW: ur, O_TRUNC: Sr, O_WRONLY: yr } = pr.constants;
var Rr = Number(process.env.__FAKE_FS_O_FILENAME__) || pr.constants.UV_FS_O_FILEMAP || 0;
var jn = Er && !!Rr;
var to = 512 * 1024;
var eo = Rr | Sr | wr | yr;
var mr = !Er && typeof ur == "number" ? ur | Sr | wr | yr : null;
var ms = mr !== null ? () => mr : jn ? (s3) => s3 < to ? eo : "w" : () => "w";
var ps = (s3, t, e) => {
  try {
    return wi.lchownSync(s3, t, e);
  } catch (i) {
    if (i?.code !== "ENOENT") throw i;
  }
};
var Ei = (s3, t, e, i) => {
  wi.lchown(s3, t, e, (r) => {
    i(r && r?.code !== "ENOENT" ? r : null);
  });
};
var io = (s3, t, e, i, r) => {
  if (t.isDirectory()) Es(we.resolve(s3, t.name), e, i, (n) => {
    if (n) return r(n);
    let o = we.resolve(s3, t.name);
    Ei(o, e, i, r);
  });
  else {
    let n = we.resolve(s3, t.name);
    Ei(n, e, i, r);
  }
};
var Es = (s3, t, e, i) => {
  wi.readdir(s3, { withFileTypes: true }, (r, n) => {
    if (r) {
      if (r.code === "ENOENT") return i();
      if (r.code !== "ENOTDIR" && r.code !== "ENOTSUP") return i(r);
    }
    if (r || !n.length) return Ei(s3, t, e, i);
    let o = n.length, h = null, a = (l) => {
      if (!h) {
        if (l) return i(h = l);
        if (--o === 0) return Ei(s3, t, e, i);
      }
    };
    for (let l of n) io(s3, l, t, e, a);
  });
};
var so = (s3, t, e, i) => {
  t.isDirectory() && ws(we.resolve(s3, t.name), e, i), ps(we.resolve(s3, t.name), e, i);
};
var ws = (s3, t, e) => {
  let i;
  try {
    i = wi.readdirSync(s3, { withFileTypes: true });
  } catch (r) {
    let n = r;
    if (n?.code === "ENOENT") return;
    if (n?.code === "ENOTDIR" || n?.code === "ENOTSUP") return ps(s3, t, e);
    throw n;
  }
  for (let r of i) so(s3, r, t, e);
  return ps(s3, t, e);
};
var Se = class extends Error {
  path;
  code;
  syscall = "chdir";
  constructor(t, e) {
    super(`${e}: Cannot cd into '${t}'`), this.path = t, this.code = e;
  }
  get name() {
    return "CwdError";
  }
};
var St = class extends Error {
  path;
  symlink;
  syscall = "symlink";
  code = "TAR_SYMLINK_ERROR";
  constructor(t, e) {
    super("TAR_SYMLINK_ERROR: Cannot extract through symbolic link"), this.symlink = t, this.path = e;
  }
  get name() {
    return "SymlinkError";
  }
};
var no = (s3, t) => {
  k.stat(s3, (e, i) => {
    (e || !i.isDirectory()) && (e = new Se(s3, e?.code || "ENOTDIR")), t(e);
  });
};
var gr = (s3, t, e) => {
  s3 = f(s3);
  let i = t.umask ?? 18, r = t.mode | 448, n = (r & i) !== 0, o = t.uid, h = t.gid, a = typeof o == "number" && typeof h == "number" && (o !== t.processUid || h !== t.processGid), l = t.preserve, c = t.unlink, d = f(t.cwd), y = (E, x) => {
    E ? e(E) : x && a ? Es(x, o, h, (Le) => y(Le)) : n ? k.chmod(s3, r, e) : e();
  };
  if (s3 === d) return no(s3, y);
  if (l) return ro.mkdir(s3, { mode: r, recursive: true }).then((E) => y(null, E ?? void 0), y);
  let D = f(Si.relative(d, s3)).split("/");
  Ss(d, D, r, c, d, void 0, y);
};
var Ss = (s3, t, e, i, r, n, o) => {
  if (t.length === 0) return o(null, n);
  let h = t.shift(), a = f(Si.resolve(s3 + "/" + h));
  k.mkdir(a, e, br(a, t, e, i, r, n, o));
};
var br = (s3, t, e, i, r, n, o) => (h) => {
  h ? k.lstat(s3, (a, l) => {
    if (a) a.path = a.path && f(a.path), o(a);
    else if (l.isDirectory()) Ss(s3, t, e, i, r, n, o);
    else if (i) k.unlink(s3, (c) => {
      if (c) return o(c);
      k.mkdir(s3, e, br(s3, t, e, i, r, n, o));
    });
    else {
      if (l.isSymbolicLink()) return o(new St(s3, s3 + "/" + t.join("/")));
      o(h);
    }
  }) : (n = n || s3, Ss(s3, t, e, i, r, n, o));
};
var oo = (s3) => {
  let t = false, e;
  try {
    t = k.statSync(s3).isDirectory();
  } catch (i) {
    e = i?.code;
  } finally {
    if (!t) throw new Se(s3, e ?? "ENOTDIR");
  }
};
var _r = (s3, t) => {
  s3 = f(s3);
  let e = t.umask ?? 18, i = t.mode | 448, r = (i & e) !== 0, n = t.uid, o = t.gid, h = typeof n == "number" && typeof o == "number" && (n !== t.processUid || o !== t.processGid), a = t.preserve, l = t.unlink, c = f(t.cwd), d = (E) => {
    E && h && ws(E, n, o), r && k.chmodSync(s3, i);
  };
  if (s3 === c) return oo(c), d();
  if (a) return d(k.mkdirSync(s3, { mode: i, recursive: true }) ?? void 0);
  let T = f(Si.relative(c, s3)).split("/"), D;
  for (let E = T.shift(), x = c; E && (x += "/" + E); E = T.shift()) {
    x = f(Si.resolve(x));
    try {
      k.mkdirSync(x, i), D = D || x;
    } catch {
      let Le = k.lstatSync(x);
      if (Le.isDirectory()) continue;
      if (l) {
        k.unlinkSync(x), k.mkdirSync(x, i), D = D || x;
        continue;
      } else if (Le.isSymbolicLink()) return new St(x, x + "/" + T.join("/"));
    }
  }
  return d(D);
};
var ys = /* @__PURE__ */ Object.create(null);
var Or = 1e4;
var Vt = /* @__PURE__ */ new Set();
var Tr = (s3) => {
  Vt.has(s3) ? Vt.delete(s3) : ys[s3] = s3.normalize("NFD").toLocaleLowerCase("en").toLocaleUpperCase("en"), Vt.add(s3);
  let t = ys[s3], e = Vt.size - Or;
  if (e > Or / 10) {
    for (let i of Vt) if (Vt.delete(i), delete ys[i], --e <= 0) break;
  }
  return t;
};
var ho = process.env.TESTING_TAR_FAKE_PLATFORM || process.platform;
var ao = ho === "win32";
var lo = (s3) => s3.split("/").slice(0, -1).reduce((e, i) => {
  let r = e.at(-1);
  return r !== void 0 && (i = xr(r, i)), e.push(i || "/"), e;
}, []);
var yi = class {
  #t = /* @__PURE__ */ new Map();
  #i = /* @__PURE__ */ new Map();
  #s = /* @__PURE__ */ new Set();
  reserve(t, e) {
    t = ao ? ["win32 parallelization disabled"] : t.map((r) => mt(xr(Tr(r))));
    let i = new Set(t.map((r) => lo(r)).reduce((r, n) => r.concat(n)));
    this.#i.set(e, { dirs: i, paths: t });
    for (let r of t) {
      let n = this.#t.get(r);
      n ? n.push(e) : this.#t.set(r, [e]);
    }
    for (let r of i) {
      let n = this.#t.get(r);
      if (!n) this.#t.set(r, [/* @__PURE__ */ new Set([e])]);
      else {
        let o = n.at(-1);
        o instanceof Set ? o.add(e) : n.push(/* @__PURE__ */ new Set([e]));
      }
    }
    return this.#r(e);
  }
  #n(t) {
    let e = this.#i.get(t);
    if (!e) throw new Error("function does not have any path reservations");
    return { paths: e.paths.map((i) => this.#t.get(i)), dirs: [...e.dirs].map((i) => this.#t.get(i)) };
  }
  check(t) {
    let { paths: e, dirs: i } = this.#n(t);
    return e.every((r) => r && r[0] === t) && i.every((r) => r && r[0] instanceof Set && r[0].has(t));
  }
  #r(t) {
    return this.#s.has(t) || !this.check(t) ? false : (this.#s.add(t), t(() => this.#e(t)), true);
  }
  #e(t) {
    if (!this.#s.has(t)) return false;
    let e = this.#i.get(t);
    if (!e) throw new Error("invalid reservation");
    let { paths: i, dirs: r } = e, n = /* @__PURE__ */ new Set();
    for (let o of i) {
      let h = this.#t.get(o);
      if (!h || h?.[0] !== t) continue;
      let a = h[1];
      if (!a) {
        this.#t.delete(o);
        continue;
      }
      if (h.shift(), typeof a == "function") n.add(a);
      else for (let l of a) n.add(l);
    }
    for (let o of r) {
      let h = this.#t.get(o), a = h?.[0];
      if (!(!h || !(a instanceof Set))) if (a.size === 1 && h.length === 1) {
        this.#t.delete(o);
        continue;
      } else if (a.size === 1) {
        h.shift();
        let l = h[0];
        typeof l == "function" && n.add(l);
      } else a.delete(t);
    }
    return this.#s.delete(t), n.forEach((o) => this.#r(o)), true;
  }
};
var Lr = () => process.umask();
var Dr = /* @__PURE__ */ Symbol("onEntry");
var _s = /* @__PURE__ */ Symbol("checkFs");
var Nr = /* @__PURE__ */ Symbol("checkFs2");
var Os = /* @__PURE__ */ Symbol("isReusable");
var P = /* @__PURE__ */ Symbol("makeFs");
var Ts = /* @__PURE__ */ Symbol("file");
var xs = /* @__PURE__ */ Symbol("directory");
var gi = /* @__PURE__ */ Symbol("link");
var Ar = /* @__PURE__ */ Symbol("symlink");
var Ir = /* @__PURE__ */ Symbol("hardlink");
var Re = /* @__PURE__ */ Symbol("ensureNoSymlink");
var Cr = /* @__PURE__ */ Symbol("unsupported");
var Fr = /* @__PURE__ */ Symbol("checkPath");
var Rs = /* @__PURE__ */ Symbol("stripAbsolutePath");
var yt = /* @__PURE__ */ Symbol("mkdir");
var O = /* @__PURE__ */ Symbol("onError");
var Ri = /* @__PURE__ */ Symbol("pending");
var kr = /* @__PURE__ */ Symbol("pend");
var $t = /* @__PURE__ */ Symbol("unpend");
var gs = /* @__PURE__ */ Symbol("ended");
var bs = /* @__PURE__ */ Symbol("maybeClose");
var Ls = /* @__PURE__ */ Symbol("skip");
var ge = /* @__PURE__ */ Symbol("doChown");
var be = /* @__PURE__ */ Symbol("uid");
var _e = /* @__PURE__ */ Symbol("gid");
var Oe = /* @__PURE__ */ Symbol("checkedCwd");
var fo = process.env.TESTING_TAR_FAKE_PLATFORM || process.platform;
var Te = fo === "win32";
var uo = 1024;
var mo = (s3, t) => {
  if (!Te) return u.unlink(s3, t);
  let e = s3 + ".DELETE." + Mr(16).toString("hex");
  u.rename(s3, e, (i) => {
    if (i) return t(i);
    u.unlink(e, t);
  });
};
var po = (s3) => {
  if (!Te) return u.unlinkSync(s3);
  let t = s3 + ".DELETE." + Mr(16).toString("hex");
  u.renameSync(s3, t), u.unlinkSync(t);
};
var vr = (s3, t, e) => s3 !== void 0 && s3 === s3 >>> 0 ? s3 : t !== void 0 && t === t >>> 0 ? t : e;
var Xt = class extends rt {
  [gs] = false;
  [Oe] = false;
  [Ri] = 0;
  reservations = new yi();
  transform;
  writable = true;
  readable = false;
  uid;
  gid;
  setOwner;
  preserveOwner;
  processGid;
  processUid;
  maxDepth;
  forceChown;
  win32;
  newer;
  keep;
  noMtime;
  preservePaths;
  unlink;
  cwd;
  strip;
  processUmask;
  umask;
  dmode;
  fmode;
  chmod;
  constructor(t = {}) {
    if (t.ondone = () => {
      this[gs] = true, this[bs]();
    }, super(t), this.transform = t.transform, this.chmod = !!t.chmod, typeof t.uid == "number" || typeof t.gid == "number") {
      if (typeof t.uid != "number" || typeof t.gid != "number") throw new TypeError("cannot set owner without number uid and gid");
      if (t.preserveOwner) throw new TypeError("cannot preserve owner in archive and also set owner explicitly");
      this.uid = t.uid, this.gid = t.gid, this.setOwner = true;
    } else this.uid = void 0, this.gid = void 0, this.setOwner = false;
    this.preserveOwner = t.preserveOwner === void 0 && typeof t.uid != "number" ? process.getuid?.() === 0 : !!t.preserveOwner, this.processUid = (this.preserveOwner || this.setOwner) && process.getuid ? process.getuid() : void 0, this.processGid = (this.preserveOwner || this.setOwner) && process.getgid ? process.getgid() : void 0, this.maxDepth = typeof t.maxDepth == "number" ? t.maxDepth : uo, this.forceChown = t.forceChown === true, this.win32 = !!t.win32 || Te, this.newer = !!t.newer, this.keep = !!t.keep, this.noMtime = !!t.noMtime, this.preservePaths = !!t.preservePaths, this.unlink = !!t.unlink, this.cwd = f(R.resolve(t.cwd || process.cwd())), this.strip = Number(t.strip) || 0, this.processUmask = this.chmod ? typeof t.processUmask == "number" ? t.processUmask : Lr() : 0, this.umask = typeof t.umask == "number" ? t.umask : this.processUmask, this.dmode = t.dmode || 511 & ~this.umask, this.fmode = t.fmode || 438 & ~this.umask, this.on("entry", (e) => this[Dr](e));
  }
  warn(t, e, i = {}) {
    return (t === "TAR_BAD_ARCHIVE" || t === "TAR_ABORT") && (i.recoverable = false), super.warn(t, e, i);
  }
  [bs]() {
    this[gs] && this[Ri] === 0 && (this.emit("prefinish"), this.emit("finish"), this.emit("end"));
  }
  [Rs](t, e) {
    let i = t[e], { type: r } = t;
    if (!i || this.preservePaths) return true;
    let [n, o] = ce(i), h = o.replaceAll(/\\/g, "/").split("/");
    if (h.includes("..") || Te && /^[a-z]:\.\.$/i.test(h[0] ?? "")) {
      if (e === "path" || r === "Link") return this.warn("TAR_ENTRY_ERROR", `${e} contains '..'`, { entry: t, [e]: i }), false;
      let a = R.posix.dirname(t.path), l = R.posix.normalize(R.posix.join(a, h.join("/")));
      if (l.startsWith("../") || l === "..") return this.warn("TAR_ENTRY_ERROR", `${e} escapes extraction directory`, { entry: t, [e]: i }), false;
    }
    return n && (t[e] = String(o), this.warn("TAR_ENTRY_INFO", `stripping ${n} from absolute ${e}`, { entry: t, [e]: i })), true;
  }
  [Fr](t) {
    let e = f(t.path), i = e.split("/");
    if (this.strip) {
      if (i.length < this.strip) return false;
      if (t.type === "Link") {
        let r = f(String(t.linkpath)).split("/");
        if (r.length >= this.strip) t.linkpath = r.slice(this.strip).join("/");
        else return false;
      }
      i.splice(0, this.strip), t.path = i.join("/");
    }
    if (isFinite(this.maxDepth) && i.length > this.maxDepth) return this.warn("TAR_ENTRY_ERROR", "path excessively deep", { entry: t, path: e, depth: i.length, maxDepth: this.maxDepth }), false;
    if (!this[Rs](t, "path") || !this[Rs](t, "linkpath")) return false;
    if (t.absolute = R.isAbsolute(t.path) ? f(R.resolve(t.path)) : f(R.resolve(this.cwd, t.path)), !this.preservePaths && typeof t.absolute == "string" && t.absolute.indexOf(this.cwd + "/") !== 0 && t.absolute !== this.cwd) return this.warn("TAR_ENTRY_ERROR", "path escaped extraction target", { entry: t, path: f(t.path), resolvedPath: t.absolute, cwd: this.cwd }), false;
    if (t.absolute === this.cwd && t.type !== "Directory" && t.type !== "GNUDumpDir") return false;
    if (this.win32) {
      let { root: r } = R.win32.parse(String(t.absolute));
      t.absolute = r + ts(String(t.absolute).slice(r.length));
      let { root: n } = R.win32.parse(t.path);
      t.path = n + ts(t.path.slice(n.length));
    }
    return true;
  }
  [Dr](t) {
    if (!this[Fr](t)) return t.resume();
    switch (co.equal(typeof t.absolute, "string"), t.type) {
      case "Directory":
      case "GNUDumpDir":
        t.mode && (t.mode = t.mode | 448);
      case "File":
      case "OldFile":
      case "ContiguousFile":
      case "Link":
      case "SymbolicLink":
        return this[_s](t);
      default:
        return this[Cr](t);
    }
  }
  [O](t, e) {
    t.name === "CwdError" ? this.emit("error", t) : (this.warn("TAR_ENTRY_ERROR", t, { entry: e }), this[$t](), e.resume());
  }
  [yt](t, e, i) {
    gr(f(t), { uid: this.uid, gid: this.gid, processUid: this.processUid, processGid: this.processGid, umask: this.processUmask, preserve: this.preservePaths, unlink: this.unlink, cwd: this.cwd, mode: e }, i);
  }
  [ge](t) {
    return this.forceChown || this.preserveOwner && (typeof t.uid == "number" && t.uid !== this.processUid || typeof t.gid == "number" && t.gid !== this.processGid) || typeof this.uid == "number" && this.uid !== this.processUid || typeof this.gid == "number" && this.gid !== this.processGid;
  }
  [be](t) {
    return vr(this.uid, t.uid, this.processUid);
  }
  [_e](t) {
    return vr(this.gid, t.gid, this.processGid);
  }
  [Ts](t, e) {
    let i = typeof t.mode == "number" ? t.mode & 4095 : this.fmode, r = new et(String(t.absolute), { flags: ms(t.size), mode: i, autoClose: false });
    r.on("error", (a) => {
      r.fd && u.close(r.fd, () => {
      }), r.write = () => true, this[O](a, t), e();
    });
    let n = 1, o = (a) => {
      if (a) {
        r.fd && u.close(r.fd, () => {
        }), this[O](a, t), e();
        return;
      }
      --n === 0 && r.fd !== void 0 && u.close(r.fd, (l) => {
        l ? this[O](l, t) : this[$t](), e();
      });
    };
    r.on("finish", () => {
      let a = String(t.absolute), l = r.fd;
      if (typeof l == "number" && t.mtime && !this.noMtime) {
        n++;
        let c = t.atime || /* @__PURE__ */ new Date(), d = t.mtime;
        u.futimes(l, c, d, (y) => y ? u.utimes(a, c, d, (T) => o(T && y)) : o());
      }
      if (typeof l == "number" && this[ge](t)) {
        n++;
        let c = this[be](t), d = this[_e](t);
        typeof c == "number" && typeof d == "number" && u.fchown(l, c, d, (y) => y ? u.chown(a, c, d, (T) => o(T && y)) : o());
      }
      o();
    });
    let h = this.transform && this.transform(t) || t;
    h !== t && (h.on("error", (a) => {
      this[O](a, t), e();
    }), t.pipe(h)), h.pipe(r);
  }
  [xs](t, e) {
    let i = typeof t.mode == "number" ? t.mode & 4095 : this.dmode;
    this[yt](String(t.absolute), i, (r) => {
      if (r) {
        this[O](r, t), e();
        return;
      }
      let n = 1, o = () => {
        --n === 0 && (e(), this[$t](), t.resume());
      };
      t.mtime && !this.noMtime && (n++, u.utimes(String(t.absolute), t.atime || /* @__PURE__ */ new Date(), t.mtime, o)), this[ge](t) && (n++, u.chown(String(t.absolute), Number(this[be](t)), Number(this[_e](t)), o)), o();
    });
  }
  [Cr](t) {
    t.unsupported = true, this.warn("TAR_ENTRY_UNSUPPORTED", `unsupported entry type: ${t.type}`, { entry: t }), t.resume();
  }
  [Ar](t, e) {
    let i = f(R.relative(this.cwd, R.resolve(R.dirname(String(t.absolute)), String(t.linkpath)))).split("/");
    this[Re](t, this.cwd, i, () => this[gi](t, String(t.linkpath), "symlink", e), (r) => {
      this[O](r, t), e();
    });
  }
  [Ir](t, e) {
    let i = f(R.resolve(this.cwd, String(t.linkpath))), r = f(String(t.linkpath)).split("/");
    this[Re](t, this.cwd, r, () => this[gi](t, i, "link", e), (n) => {
      this[O](n, t), e();
    });
  }
  [Re](t, e, i, r, n) {
    let o = i.shift();
    if (this.preservePaths || o === void 0) return r();
    let h = R.resolve(e, o);
    u.lstat(h, (a, l) => {
      if (a) return r();
      if (l?.isSymbolicLink()) return n(new St(h, R.resolve(h, i.join("/"))));
      this[Re](t, h, i, r, n);
    });
  }
  [kr]() {
    this[Ri]++;
  }
  [$t]() {
    this[Ri]--, this[bs]();
  }
  [Ls](t) {
    this[$t](), t.resume();
  }
  [Os](t, e) {
    return t.type === "File" && !this.unlink && e.isFile() && e.nlink <= 1 && !Te;
  }
  [_s](t) {
    this[kr]();
    let e = [t.path];
    t.linkpath && e.push(t.linkpath), this.reservations.reserve(e, (i) => this[Nr](t, i));
  }
  [Nr](t, e) {
    let i = (h) => {
      e(h);
    }, r = () => {
      this[yt](this.cwd, this.dmode, (h) => {
        if (h) {
          this[O](h, t), i();
          return;
        }
        this[Oe] = true, n();
      });
    }, n = () => {
      if (t.absolute !== this.cwd) {
        let h = f(R.dirname(String(t.absolute)));
        if (h !== this.cwd) return this[yt](h, this.dmode, (a) => {
          if (a) {
            this[O](a, t), i();
            return;
          }
          o();
        });
      }
      o();
    }, o = () => {
      u.lstat(String(t.absolute), (h, a) => {
        if (a && (this.keep || this.newer && a.mtime > (t.mtime ?? a.mtime))) {
          this[Ls](t), i();
          return;
        }
        if (h || this[Os](t, a)) return this[P](null, t, i);
        if (a.isDirectory()) {
          if (t.type === "Directory") {
            let l = this.chmod && t.mode && (a.mode & 4095) !== t.mode, c = (d) => this[P](d ?? null, t, i);
            return l ? u.chmod(String(t.absolute), Number(t.mode), c) : c();
          }
          if (t.absolute !== this.cwd) return u.rmdir(String(t.absolute), (l) => this[P](l ?? null, t, i));
        }
        if (t.absolute === this.cwd) return this[P](null, t, i);
        mo(String(t.absolute), (l) => this[P](l ?? null, t, i));
      });
    };
    this[Oe] ? n() : r();
  }
  [P](t, e, i) {
    if (t) {
      this[O](t, e), i();
      return;
    }
    switch (e.type) {
      case "File":
      case "OldFile":
      case "ContiguousFile":
        return this[Ts](e, i);
      case "Link":
        return this[Ir](e, i);
      case "SymbolicLink":
        return this[Ar](e, i);
      case "Directory":
      case "GNUDumpDir":
        return this[xs](e, i);
    }
  }
  [gi](t, e, i, r) {
    u[i](e, String(t.absolute), (n) => {
      n ? this[O](n, t) : (this[$t](), t.resume()), r();
    });
  }
};
var ye = (s3) => {
  try {
    return [null, s3()];
  } catch (t) {
    return [t, null];
  }
};
var xe = class extends Xt {
  sync = true;
  [P](t, e) {
    return super[P](t, e, () => {
    });
  }
  [_s](t) {
    if (!this[Oe]) {
      let n = this[yt](this.cwd, this.dmode);
      if (n) return this[O](n, t);
      this[Oe] = true;
    }
    if (t.absolute !== this.cwd) {
      let n = f(R.dirname(String(t.absolute)));
      if (n !== this.cwd) {
        let o = this[yt](n, this.dmode);
        if (o) return this[O](o, t);
      }
    }
    let [e, i] = ye(() => u.lstatSync(String(t.absolute)));
    if (i && (this.keep || this.newer && i.mtime > (t.mtime ?? i.mtime))) return this[Ls](t);
    if (e || this[Os](t, i)) return this[P](null, t);
    if (i.isDirectory()) {
      if (t.type === "Directory") {
        let o = this.chmod && t.mode && (i.mode & 4095) !== t.mode, [h] = o ? ye(() => {
          u.chmodSync(String(t.absolute), Number(t.mode));
        }) : [];
        return this[P](h, t);
      }
      let [n] = ye(() => u.rmdirSync(String(t.absolute)));
      this[P](n, t);
    }
    let [r] = t.absolute === this.cwd ? [] : ye(() => po(String(t.absolute)));
    this[P](r, t);
  }
  [Ts](t, e) {
    let i = typeof t.mode == "number" ? t.mode & 4095 : this.fmode, r = (h) => {
      let a;
      try {
        u.closeSync(n);
      } catch (l) {
        a = l;
      }
      (h || a) && this[O](h || a, t), e();
    }, n;
    try {
      n = u.openSync(String(t.absolute), ms(t.size), i);
    } catch (h) {
      return r(h);
    }
    let o = this.transform && this.transform(t) || t;
    o !== t && (o.on("error", (h) => this[O](h, t)), t.pipe(o)), o.on("data", (h) => {
      try {
        u.writeSync(n, h, 0, h.length);
      } catch (a) {
        r(a);
      }
    }), o.on("end", () => {
      let h = null;
      if (t.mtime && !this.noMtime) {
        let a = t.atime || /* @__PURE__ */ new Date(), l = t.mtime;
        try {
          u.futimesSync(n, a, l);
        } catch (c) {
          try {
            u.utimesSync(String(t.absolute), a, l);
          } catch {
            h = c;
          }
        }
      }
      if (this[ge](t)) {
        let a = this[be](t), l = this[_e](t);
        try {
          u.fchownSync(n, Number(a), Number(l));
        } catch (c) {
          try {
            u.chownSync(String(t.absolute), Number(a), Number(l));
          } catch {
            h = h || c;
          }
        }
      }
      r(h);
    });
  }
  [xs](t, e) {
    let i = typeof t.mode == "number" ? t.mode & 4095 : this.dmode, r = this[yt](String(t.absolute), i);
    if (r) {
      this[O](r, t), e();
      return;
    }
    if (t.mtime && !this.noMtime) try {
      u.utimesSync(String(t.absolute), t.atime || /* @__PURE__ */ new Date(), t.mtime);
    } catch {
    }
    if (this[ge](t)) try {
      u.chownSync(String(t.absolute), Number(this[be](t)), Number(this[_e](t)));
    } catch {
    }
    e(), t.resume();
  }
  [yt](t, e) {
    try {
      return _r(f(t), { uid: this.uid, gid: this.gid, processUid: this.processUid, processGid: this.processGid, umask: this.processUmask, preserve: this.preservePaths, unlink: this.unlink, cwd: this.cwd, mode: e });
    } catch (i) {
      return i;
    }
  }
  [Re](t, e, i, r, n) {
    if (this.preservePaths || i.length === 0) return r();
    let o = e;
    for (let h of i) {
      o = R.resolve(o, h);
      let [a, l] = ye(() => u.lstatSync(o));
      if (a) return r();
      if (l.isSymbolicLink()) return n(new St(o, R.resolve(e, i.join("/"))));
    }
    r();
  }
  [gi](t, e, i, r) {
    let n = `${i}Sync`;
    try {
      u[n](e, String(t.absolute)), r(), t.resume();
    } catch (o) {
      return this[O](o, t);
    }
  }
};
var Eo = (s3) => {
  let t = new xe(s3), e = s3.file, i = Br.statSync(e), r = s3.maxReadSize || 16 * 1024 * 1024;
  new Be(e, { readSize: r, size: i.size }).pipe(t);
};
var wo = (s3, t) => {
  let e = new Xt(s3), i = s3.maxReadSize || 16 * 1024 * 1024, r = s3.file;
  return new Promise((o, h) => {
    e.on("error", h), e.on("close", o), Br.stat(r, (a, l) => {
      if (a) h(a);
      else {
        let c = new _t(r, { readSize: i, size: l.size });
        c.on("error", h), c.pipe(e);
      }
    });
  });
};
var So = K(Eo, wo, (s3) => new xe(s3), (s3) => new Xt(s3), (s3, t) => {
  t?.length && Qi(s3, t);
});
var yo = (s3, t) => {
  let e = new kt(s3), i = true, r, n;
  try {
    try {
      r = v.openSync(s3.file, "r+");
    } catch (a) {
      if (a?.code === "ENOENT") r = v.openSync(s3.file, "w+");
      else throw a;
    }
    let o = v.fstatSync(r), h = Buffer.alloc(512);
    t: for (n = 0; n < o.size; n += 512) {
      for (let c = 0, d = 0; c < 512; c += d) {
        if (d = v.readSync(r, h, c, h.length - c, n + c), n === 0 && h[0] === 31 && h[1] === 139) throw new Error("cannot append to compressed archives");
        if (!d) break t;
      }
      let a = new F(h);
      if (!a.cksumValid) break;
      let l = 512 * Math.ceil((a.size || 0) / 512);
      if (n + l + 512 > o.size) break;
      n += l, s3.mtimeCache && a.mtime && s3.mtimeCache.set(String(a.path), a.mtime);
    }
    i = false, Ro(s3, e, n, r, t);
  } finally {
    if (i) try {
      v.closeSync(r);
    } catch {
    }
  }
};
var Ro = (s3, t, e, i, r) => {
  let n = new Wt(s3.file, { fd: i, start: e });
  t.pipe(n), bo(t, r);
};
var go = (s3, t) => {
  t = Array.from(t);
  let e = new wt(s3), i = (n, o, h) => {
    let a = (T, D) => {
      T ? v.close(n, (E) => h(T)) : h(null, D);
    }, l = 0;
    if (o === 0) return a(null, 0);
    let c = 0, d = Buffer.alloc(512), y = (T, D) => {
      if (T || D === void 0) return a(T);
      if (c += D, c < 512 && D) return v.read(n, d, c, d.length - c, l + c, y);
      if (l === 0 && d[0] === 31 && d[1] === 139) return a(new Error("cannot append to compressed archives"));
      if (c < 512) return a(null, l);
      let E = new F(d);
      if (!E.cksumValid) return a(null, l);
      let x = 512 * Math.ceil((E.size ?? 0) / 512);
      if (l + x + 512 > o || (l += x + 512, l >= o)) return a(null, l);
      s3.mtimeCache && E.mtime && s3.mtimeCache.set(String(E.path), E.mtime), c = 0, v.read(n, d, 0, 512, l, y);
    };
    v.read(n, d, 0, 512, l, y);
  };
  return new Promise((n, o) => {
    e.on("error", o);
    let h = "r+", a = (l, c) => {
      if (l && l.code === "ENOENT" && h === "r+") return h = "w+", v.open(s3.file, h, a);
      if (l || !c) return o(l);
      v.fstat(c, (d, y) => {
        if (d) return v.close(c, () => o(d));
        i(c, y.size, (T, D) => {
          if (T) return o(T);
          let E = new et(s3.file, { fd: c, start: D });
          e.pipe(E), E.on("error", o), E.on("close", n), _o(e, t);
        });
      });
    };
    v.open(s3.file, h, a);
  });
};
var bo = (s3, t) => {
  t.forEach((e) => {
    e.charAt(0) === "@" ? Ct({ file: Pr.resolve(s3.cwd, e.slice(1)), sync: true, noResume: true, onReadEntry: (i) => s3.add(i) }) : s3.add(e);
  }), s3.end();
};
var _o = async (s3, t) => {
  for (let e of t) e.charAt(0) === "@" ? await Ct({ file: Pr.resolve(String(s3.cwd), e.slice(1)), noResume: true, onReadEntry: (i) => s3.add(i) }) : s3.add(e);
  s3.end();
};
var vt = K(yo, go, () => {
  throw new TypeError("file is required");
}, () => {
  throw new TypeError("file is required");
}, (s3, t) => {
  if (!Bs(s3)) throw new TypeError("file is required");
  if (s3.gzip || s3.brotli || s3.zstd || s3.file.endsWith(".br") || s3.file.endsWith(".tbr")) throw new TypeError("cannot append to compressed archives");
  if (!t?.length) throw new TypeError("no paths specified to add/replace");
});
var Oo = K(vt.syncFile, vt.asyncFile, vt.syncNoFile, vt.asyncNoFile, (s3, t = []) => {
  vt.validate?.(s3, t), To(s3);
});
var To = (s3) => {
  let t = s3.filter;
  s3.mtimeCache || (s3.mtimeCache = /* @__PURE__ */ new Map()), s3.filter = t ? (e, i) => t(e, i) && !((s3.mtimeCache?.get(e) ?? i.mtime ?? 0) > (i.mtime ?? 0)) : (e, i) => !((s3.mtimeCache?.get(e) ?? i.mtime ?? 0) > (i.mtime ?? 0));
};

// cli/src/preview.ts
import { createReadStream as createReadStream2, createWriteStream } from "node:fs";
import { mkdir as mkdir2, mkdtemp, readFile as readFile2, rm as rm2, writeFile as writeFile2 } from "node:fs/promises";
import { dirname, join as join4 } from "node:path";
import { createInterface as createInterface2 } from "node:readline";
import { pipeline } from "node:stream/promises";

// cli/src/pii.ts
import { isIPv4, isIPv6 } from "node:net";
var digitsOf = (s3) => s3.replace(/\D/g, "");
function validateLuhn(value) {
  const digits = digitsOf(value);
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    const d = Number(digits[digits.length - 1 - i]);
    sum += i % 2 ? d * 2 > 9 ? d * 2 - 9 : d * 2 : d;
  }
  return digits.length > 0 && sum % 10 === 0;
}
var IBAN_LENGTHS = {
  AD: 24,
  AE: 23,
  AL: 28,
  AT: 20,
  AZ: 28,
  BA: 20,
  BE: 16,
  BG: 22,
  BH: 22,
  BI: 27,
  BR: 29,
  BY: 28,
  CH: 21,
  CR: 21,
  CY: 28,
  CZ: 24,
  DE: 22,
  DJ: 27,
  DK: 18,
  DO: 28,
  EE: 20,
  EG: 29,
  ES: 24,
  FI: 18,
  FK: 18,
  FO: 18,
  FR: 27,
  GB: 22,
  GE: 22,
  GI: 23,
  GL: 18,
  GR: 27,
  GT: 28,
  HN: 28,
  HR: 21,
  HU: 28,
  IE: 22,
  IL: 23,
  IQ: 23,
  IS: 26,
  IT: 27,
  JO: 30,
  KW: 30,
  KZ: 20,
  LB: 28,
  LC: 32,
  LI: 21,
  LT: 20,
  LU: 20,
  LV: 21,
  LY: 25,
  MC: 27,
  MD: 24,
  ME: 22,
  MK: 19,
  MN: 20,
  MR: 27,
  MT: 31,
  MU: 30,
  NI: 28,
  NL: 18,
  NO: 15,
  OM: 23,
  PK: 24,
  PL: 28,
  PS: 29,
  PT: 25,
  QA: 29,
  RO: 24,
  RS: 22,
  RU: 33,
  SA: 24,
  SC: 31,
  SD: 18,
  SE: 24,
  SI: 19,
  SK: 24,
  SM: 27,
  SO: 23,
  ST: 25,
  SV: 28,
  TL: 23,
  TN: 24,
  TR: 26,
  UA: 29,
  VA: 22,
  VG: 24,
  XK: 20,
  YE: 30
};
function validateIBAN(value) {
  const iban = value.replace(/[\s.-]/g, "").toUpperCase();
  if (IBAN_LENGTHS[iban.slice(0, 2)] !== iban.length || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) return false;
  const n = `${iban.slice(4)}${iban.slice(0, 4)}`.replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  return BigInt(n) % 97n === 1n;
}
function validateSSN(value) {
  const d = digitsOf(value);
  const area = Number(d.slice(0, 3));
  return d.length === 9 && area !== 0 && area !== 666 && area < 900 && d.slice(3, 5) !== "00" && d.slice(5) !== "0000";
}
function validateNINO(value) {
  const nino = value.replace(/\s/g, "").toUpperCase();
  return /^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$/.test(nino) && !/^(?:BG|GB|NK|KN|TN|NT|ZZ)/.test(nino);
}
var VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
];
var VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4]];
for (let i = 2; i < 8; i++) VERHOEFF_P.push(VERHOEFF_P[1].map((j2) => VERHOEFF_P[i - 1][j2]));
function validateVerhoeff(value) {
  const digits = digitsOf(value);
  if (!digits) return false;
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(digits[digits.length - 1 - i])]];
  }
  return c === 0;
}
var UPI_HANDLES = [
  "okhdfcbank",
  "okicici",
  "oksbi",
  "okaxis",
  "ybl",
  "ibl",
  "axl",
  "paytm",
  "ptyes",
  "pthdfc",
  "ptsbi",
  "ptaxis",
  "apl",
  "yapl",
  "rapl",
  "upi",
  "waicici",
  "wahdfcbank",
  "wasbi",
  "waaxis",
  "axisbank",
  "hdfcbank",
  "icici",
  "sbi",
  "kotak",
  "kmbl",
  "idfcbank",
  "yesbank",
  "indus",
  "federal",
  "rbl",
  "aubank",
  "kbl",
  "cnrb",
  "pnb",
  "unionbank",
  "boi",
  "mahb",
  "barodampay",
  "airtel",
  "freecharge",
  "jupiteraxis",
  "fam",
  "slice",
  "naviaxis",
  "superyes",
  "abfspay",
  "ikwik",
  "postbank",
  "dlb",
  "axisb",
  "yescred",
  "fifederal",
  "okbizaxis",
  "jio",
  "mbk",
  "idbi",
  "iob",
  "hsbc",
  "sc"
];
function label(words) {
  const lower = words.join("|");
  const upper = words.map((w2) => w2.toUpperCase()).join("|");
  const title = words.map((w2) => w2[0].toUpperCase() + w2.slice(1)).join("|");
  const suffix = "(?:[ _]?(?:no|No|NO|num|Num|NUM|number|Number|NUMBER))?";
  return `(?:(?<![A-Za-z])(?:${lower}|${upper})|(?<![A-Z])(?:${title}))${suffix}(?![a-z])[\\s"':=#.-]{1,6}`;
}
function personalIPv4(ip) {
  if (!isIPv4(ip)) return false;
  const [a = 0, b2 = 0, c = 0, d = 0] = ip.split(".").map(Number);
  if (a < 10 && b2 < 10 && c < 10 && d < 10) return false;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b2 === 254 || a === 172 && b2 >= 16 && b2 <= 31 || a === 192 && b2 === 168);
}
function personalIPv6(ip) {
  return isIPv6(ip) && /^[23][\da-f]{3}:/i.test(ip);
}
var PII_RULES = [
  {
    id: "email",
    re: /(?<![\p{L}\p{N}_.%+])[\p{L}\p{N}_][\p{L}\p{N}_.%+'-]{0,63}(?:@|%40)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){0,8}\.[A-Za-z]{2,24}/gu,
    placeholder: "<EMAIL>",
    // `git@host` is a git remote, not a person's address.
    valid: (m2) => !/^git(?:@|%40)/i.test(m2)
  },
  {
    id: "card-number",
    re: /(?<![\w.-])(?:[2-68]\d{3}([ .-]?)\d{4}\1\d{4}\1\d{1,7}|3[47]\d{2}([ .-]?)\d{6}\2\d{5})(?![\w-]|\.\d)/g,
    placeholder: "<CARD_NUMBER>",
    valid: (m2) => digitsOf(m2).length >= 13 && validateLuhn(m2)
  },
  {
    id: "iban",
    re: /(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])/gi,
    placeholder: "<IBAN>",
    valid: validateIBAN,
    shrink: / ?[A-Z0-9]{1,4}$/i
  },
  {
    id: "ssn",
    re: /(?<![\w-])\d{3}([ -])\d{2}\1\d{4}(?![\w-])/g,
    placeholder: "<SSN>",
    valid: validateSSN
  },
  {
    id: "national-id",
    re: /(?<![A-Za-z0-9])[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D](?![A-Za-z0-9])/g,
    placeholder: "<NATIONAL_ID>",
    valid: validateNINO
  },
  {
    // Aadhaar. Ungrouped only right after its label, because a tenth of all 12-digit numbers (AWS
    // account IDs, timestamps) pass the checksum.
    id: "national-id",
    re: new RegExp(
      String.raw`(?<![\w.-])[2-9]\d{3}[ .-]\d{4}[ .-]\d{4}(?![\w-]|\.\d)|(?<=${label(["aadhaar", "aadhar", "uidai"])})[2-9]\d{11}(?!\w)`,
      "g"
    ),
    placeholder: "<NATIONAL_ID>",
    valid: validateVerhoeff
  },
  {
    // PAN: the fourth letter is the holder type (P person, C company, H family, ...).
    id: "national-id",
    re: /(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Za-z0-9])/g,
    placeholder: "<NATIONAL_ID>"
  },
  {
    id: "upi-id",
    re: new RegExp(
      `(?<![\\w.-])(?:[\\w.-]{2,256}@(?:${UPI_HANDLES.join("|")})|\\d{10}@[a-z]{2,32})(?![\\w.-])`,
      "gi"
    ),
    placeholder: "<UPI_ID>"
  },
  {
    id: "national-id",
    re: /(?<![\w-])\d{3}([ -])\d{3}\1\d{3}(?![\w-])/g,
    placeholder: "<NATIONAL_ID>",
    valid: (m2) => digitsOf(m2) !== "000000000" && validateLuhn(m2)
  },
  {
    id: "ip-address",
    re: /(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)/g,
    placeholder: "<IP_ADDRESS>",
    valid: personalIPv4
  },
  {
    id: "ip-address",
    re: /(?<![\w:.])(?=[\dA-Fa-f:]{0,39}\d)[\dA-Fa-f]{0,4}(?::[\dA-Fa-f]{0,4}){2,7}(?![\w:])/g,
    placeholder: "<IP_ADDRESS>",
    valid: personalIPv6
  },
  {
    // Indian mobile. Ten bare digits are a count or an ID far more often, so they need a prefix,
    // a space or dashes, or a label like "phone" just before.
    id: "phone",
    re: new RegExp(
      String.raw`(?<![\w+/.-])(?:\+91[ -]?[6-9]\d{4}[ -]?\d{5}|(?:91|0)[ -][6-9]\d{4}[ -]?\d{5}|[6-9]\d{4} \d{5}|[6-9]\d{3}([ -])\d{3}\1\d{3}|[6-9]\d([ -])\d{4}\2\d{4}|(?<=${label(["phone", "mobile", "mob", "cell", "cellphone", "contact", "whatsapp", "tel", "telephone"])})(?:\+?91|0)?[6-9]\d{9})(?![\w-]|\.\d)`,
      "g"
    ),
    placeholder: "<PHONE>",
    // An exact multiple of 1024 is a byte size (8589934592), not a phone number.
    valid: (m2) => Number(m2.replace(/\D/g, "").slice(-10)) % 1024 !== 0
  },
  {
    // Written like a phone number: with a `+` country code, `(415) 555-0132`, `415-555-0132` or
    // `415 555 0132`. A bare run of digits is an ID or a timestamp far more often.
    id: "phone",
    re: /(?<![\w+/.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,5}(?:[ .-]\d{2,8}){1,4}|\+\d{1,3}[ .-]?\d{2,5}[ .-]?\d{2,8}|(?:1[ .-])?(?:\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}([ .-])\d{3}\1\d{4}))(?![\w-]|\.\d)/g,
    placeholder: "<PHONE>",
    // E.164 allows at most 15 digits; fewer than 10 is a diff line or an offset (`+86400000`).
    valid: (m2) => /^(?:\D*\d){10,15}\D*$/.test(m2)
  }
];
function scrubPersonalData(text, counts) {
  let s3 = text;
  for (const rule of PII_RULES) {
    s3 = s3.replace(rule.re, (m2) => {
      let v2 = m2;
      while (rule.valid && !rule.valid(v2)) {
        const shorter = rule.shrink ? v2.replace(rule.shrink, "") : v2;
        if (shorter === v2) return m2;
        v2 = shorter;
      }
      counts[rule.id] = (counts[rule.id] ?? 0) + 1;
      return rule.placeholder + m2.slice(v2.length);
    });
  }
  return s3;
}

// cli/src/redact.ts
var fixed = (s3) => () => s3;
var keep1 = (s3) => (g2) => `${g2[1] ?? ""}${s3}`;
var RULES = [
  {
    // A key cut off by `head` or a Read limit has no END line; redact to the end of the text.
    id: "private-key",
    re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|[\s\S]*$)/g,
    to: fixed("<PRIVATE_KEY>")
  },
  {
    id: "anthropic-key",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,300}/g,
    to: fixed("<ANTHROPIC_KEY>")
  },
  {
    id: "openai-key",
    re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,300}/g,
    to: fixed("<OPENAI_KEY>")
  },
  {
    id: "github-token",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{22,255})/g,
    to: fixed("<GITHUB_TOKEN>")
  },
  {
    id: "gitlab-token",
    re: /\bglpat-[\w-]{20,64}/g,
    to: fixed("<GITLAB_TOKEN>")
  },
  {
    id: "aws-access-key",
    re: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
    to: fixed("<AWS_ACCESS_KEY>")
  },
  {
    id: "aws-secret-key",
    re: /(\baws[\w.-]{0,20}(?:secret|sk)[\w.-]{0,20}["'\s:=]{1,5})[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/gi,
    to: keep1("<AWS_SECRET>")
  },
  {
    id: "slack-token",
    re: /\bxox[abeoprs]-[A-Za-z0-9-]{10,255}/g,
    to: fixed("<SLACK_TOKEN>")
  },
  {
    id: "slack-webhook",
    re: /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[\w/+-]{20,200}/g,
    to: fixed("<SLACK_WEBHOOK>")
  },
  {
    id: "stripe-key",
    re: /\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b/g,
    to: fixed("<STRIPE_KEY>")
  },
  {
    id: "google-api-key",
    re: /\bAIza[A-Za-z0-9_-]{35}/g,
    to: fixed("<GOOGLE_API_KEY>")
  },
  {
    id: "google-oauth",
    re: /\b(?:ya29\.[\w-]{20,2048}|GOCSPX-[\w-]{28})/g,
    to: fixed("<GOOGLE_OAUTH>")
  },
  { id: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, to: fixed("<NPM_TOKEN>") },
  {
    id: "pypi-token",
    re: /\bpypi-AgEIcHlwaS5vcmc[\w-]{50,300}/g,
    to: fixed("<PYPI_TOKEN>")
  },
  {
    id: "huggingface-token",
    re: /\bhf_[A-Za-z]{34,64}\b/g,
    to: fixed("<HF_TOKEN>")
  },
  {
    id: "sendgrid-key",
    re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/g,
    to: fixed("<SENDGRID_KEY>")
  },
  {
    id: "databricks-token",
    re: /\bdapi[a-f0-9]{32}(?:-\d)?\b/g,
    to: fixed("<DATABRICKS_TOKEN>")
  },
  { id: "twilio-key", re: /\bSK[0-9a-fA-F]{32}\b/g, to: fixed("<TWILIO_KEY>") },
  {
    id: "azure-client-secret",
    re: /\b[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}\b/g,
    to: fixed("<AZURE_SECRET>")
  },
  {
    id: "azure-sas",
    re: /([?&]sig=)[^&\s"']{1,512}/g,
    to: keep1("<SIGNATURE>")
  },
  {
    id: "jwt",
    re: /\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}/g,
    to: fixed("<JWT>")
  },
  {
    id: "auth-header",
    re: /\b((?:Proxy-)?Authorization\s{0,5}:\s{0,5}(?:[A-Za-z-]{1,20}\s{1,5})?)[^\s"'<]{8,4096}/gi,
    to: keep1("<TOKEN>")
  },
  {
    id: "cookie-header",
    re: /\b((?:Set-)?Cookie\s{0,5}:\s{0,5})[^\r\n"'<]{1,4096}/gi,
    to: keep1("<COOKIE>")
  },
  {
    id: "bearer-token",
    re: /\b([Bb]earer\s{1,5})[A-Za-z0-9._~+/-]{20,4096}=*/g,
    to: keep1("<TOKEN>")
  },
  {
    id: "url-credentials",
    re: /(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s/:@'"]{0,256}:[^\s'"]{0,512}@/gi,
    to: keep1("<CREDENTIALS>@")
  },
  {
    id: "cli-password",
    re: /(\s--?(?:password|passwd|pass|token|api-key|secret)(?:\s{1,5}|=))(?!-|<)[^\s"']{1,512}/gi,
    to: keep1("<REDACTED>")
  },
  {
    id: "cli-password",
    re: /(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]{0,200}?\s-p)(?![\s<])[^\s"']{1,512}/g,
    to: keep1("<REDACTED>")
  },
  {
    id: "cli-password",
    re: /(\s(?:-u|--user)\s{1,5}[^\s:'"]{1,128}:)(?!<)[^\s'"]{1,512}/g,
    to: keep1("<REDACTED>")
  },
  {
    // `name = value` where the name says it holds a secret. Code that merely mentions such a
    // name (`token: string`, `getToken(req)`, `${TOKEN}`, `process.env.X`) is left alone.
    id: "secret-assignment",
    re: /(?<![\w.-])((?:\\?")?[\w.-]{0,40}?(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|account[_-]?key|credentials?|token)(?:\\?")?)(\s{0,5}[=:]\s{0,5})(?!["']?<|[A-Za-z_$][\w$.]{0,100}\s{0,5}[(;]|(?:string|number|boolean|undefined|null|true|false)\b|\$\{|process\.env|os\.environ)(?:\\"[^"\\\n]{1,512}\\"|"[^"\n]{1,512}"|'[^'\n]{1,512}'|[^\s"',;}<)\\]{4,512})/gi,
    to: (g2) => `${g2[1] ?? ""}${g2[2] ?? ""}<REDACTED>`
  }
];
var ENV_LINE = /^(\s{0,20}(?:\d{1,9}[→\t]\s{0,5})?(?:export\s{1,5})?[A-Z][A-Z0-9_]{0,100}\s{0,5}=\s{0,5})(\S.*)$/;
var ENV_COMMENT = /^\s{0,20}(?:\d{1,9}[→\t]\s{0,5})?#/;
var ENV_PATH = /(?:^|[/\\])(?:\.env(?:\.[\w.-]{1,40})?|\.envrc)$/;
var BASE64_BLOB = /^[A-Za-z0-9+/\r\n]{1000,}={0,2}$/;
var DATA_URI = /(data:[\w.+-]{1,64}\/[\w.+-]{1,64};base64,)[A-Za-z0-9+/=]{100,}/g;
var LONG_BASE64 = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{2000,}={0,2}/g;
var SECRET_KEY = /(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|credentials?|token|cookie|authorization)$/i;
var bump = (counts, id, n = 1) => {
  if (n) counts[id] = (counts[id] ?? 0) + n;
};
function replaceCounting(s3, re2, to2, counts, id) {
  let hits = 0;
  const out = s3.replace(re2, (...args) => {
    hits++;
    const groups = args.slice(
      0,
      args.findIndex((a) => typeof a === "number")
    );
    return to2(groups.map((g2) => typeof g2 === "string" ? g2 : ""));
  });
  bump(counts, id, hits);
  return out;
}
function maskEnvBody(text, counts) {
  const lines = text.split("\n");
  if (!lines.some((l) => ENV_LINE.test(l))) return text;
  bump(counts, "env-file");
  return lines.map((l) => ENV_COMMENT.test(l) ? l : l.replace(ENV_LINE, "$1<REDACTED>")).join("\n");
}
function scrubText(text, counts, home, envFile = false) {
  if (BASE64_BLOB.test(text)) {
    bump(counts, "base64-blob");
    return "<base64 omitted>";
  }
  let s3 = envFile ? maskEnvBody(text, counts) : text;
  s3 = replaceCounting(
    s3,
    DATA_URI,
    keep1("<base64 omitted>"),
    counts,
    "base64-blob"
  );
  s3 = replaceCounting(
    s3,
    LONG_BASE64,
    fixed("<base64 omitted>"),
    counts,
    "base64-blob"
  );
  for (const rule of RULES)
    s3 = replaceCounting(s3, rule.re, rule.to, counts, rule.id);
  s3 = scrubPersonalData(s3, counts);
  return home ? rewriteHome(s3, home, counts) : s3;
}
var GENERIC_USERS = /* @__PURE__ */ new Set([
  "root",
  "admin",
  "administrator",
  "user",
  "users",
  "ubuntu",
  "runner",
  "guest",
  "test",
  "home",
  "developer",
  "ec2-user",
  "vagrant",
  "node",
  "default",
  "local",
  "owner",
  "staff",
  "codespace",
  "jenkins",
  "circleci",
  "azureuser",
  "postgres",
  "debian",
  "centos",
  "docker",
  "nobody",
  "www-data",
  "vscode",
  "gitpod",
  "coder",
  "build",
  "sandbox",
  "cloudshell-user"
]);
function userPattern(home) {
  const user = home.split(/[/\\]/).pop() ?? "";
  if (user.length < 4 || GENERIC_USERS.has(user.toLowerCase())) return void 0;
  return new RegExp(`(?<![A-Za-z0-9])${escapeRe(user)}(?![A-Za-z0-9])`, "g");
}
function normalHome(home) {
  const h = home?.replace(/[/\\]+$/, "");
  return h && h.length >= 2 ? h : void 0;
}
function rewriteHome(text, home, counts) {
  const h = normalHome(home);
  if (!h) return text;
  let s3 = text;
  const forms = [
    [h, "(?![A-Za-z0-9_-])"],
    [encodeProjectDir(h), "(?![A-Za-z0-9])"]
  ];
  for (const [form, boundary] of forms) {
    if (s3.includes(form))
      s3 = replaceCounting(
        s3,
        new RegExp(`${escapeRe(form)}${boundary}`, "g"),
        fixed("~"),
        counts,
        "home-path"
      );
  }
  const user = userPattern(h);
  return user ? replaceCounting(s3, user, fixed("{USER}"), counts, "username") : s3;
}
function aliasProjectDir(project, home) {
  const h = normalHome(home);
  if (!h) return project;
  const enc = encodeProjectDir(h);
  const aliased = project === enc || project.startsWith(`${enc}-`) ? `~${project.slice(enc.length)}` : project;
  const user = userPattern(h);
  return user ? aliased.replace(user, "{USER}") : aliased;
}
function escapeRe(s3) {
  return s3.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
var INTERRUPT_MARKER = "[Request interrupted";
var ERROR_LINE = /^HTTP\/?\s?[45]\d\d|\b[45]\d\d Bad Gateway|^Traceback \(most recent call last\)|^\s*(?:Error|ERROR|FAILED|fatal|error)(?::|\[)|^(?:FAILED|ERROR) |command not found|No such file or directory|^[\w.]*(?:Error|Exception)\b:/;
var ERROR_WORDS = /\b(?:errors?|failed|failure|exception|exceeded|timed? ?out|timeout|cannot|can't|could not|unable to|denied|not found|invalid|unexpected|refused)\b/i;
var ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
var ERROR_MAX_LINES = 6;
var ERROR_LINE_CHARS = 200;
var ERROR_CHARS = 500;
function errorLines(output) {
  const lines = output.replace(ANSI, "").split("\n").map((l) => l.trimEnd()).filter((l) => l.trim() !== "");
  if (!lines.length) return { lines, picked: [] };
  const last = lines.length - 1;
  const formatted = lines.flatMap((l, i) => i > 0 && i < last && ERROR_LINE.test(l) ? [i] : []);
  const worded = lines.flatMap((l, i) => i > 0 && i < last && ERROR_WORDS.test(l) ? [i] : []);
  const middle = [.../* @__PURE__ */ new Set([...formatted, ...worded])].slice(0, ERROR_MAX_LINES - 2);
  return { lines, picked: [.../* @__PURE__ */ new Set([0, ...middle, last])].sort((a, b2) => a - b2) };
}
function messageFrom(lines, picked) {
  const kept = [...new Set(picked)].filter((i) => Number.isInteger(i) && i >= 0 && i < lines.length).sort((a, b2) => a - b2).slice(0, ERROR_MAX_LINES).map((i) => lines[i] ?? "").map((l) => l.length > ERROR_LINE_CHARS ? `${l.slice(0, ERROR_LINE_CHARS)}\u2026` : l);
  const message = kept.join("\n");
  return message.length > ERROR_CHARS ? `${message.slice(0, ERROR_CHARS)}\u2026` : message;
}
var CANDIDATE_HEAD = 150;
var CANDIDATE_TAIL = 100;
function candidateOf(id, lines, picked) {
  if (lines.length <= CANDIDATE_HEAD + CANDIDATE_TAIL) return { id, lines, picked };
  const tailStart = lines.length - CANDIDATE_TAIL;
  const kept = [...lines.slice(0, CANDIDATE_HEAD), ...lines.slice(tailStart)];
  const remap = picked.flatMap((i) => i < CANDIDATE_HEAD ? [i] : i >= tailStart ? [i - tailStart + CANDIDATE_HEAD] : []);
  return { id, lines: kept, picked: remap };
}
function outputText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((b2) => b2 && typeof b2 === "object" && typeof b2.text === "string" ? b2.text : "").filter(Boolean).join("\n");
}
function isImageBlock(v2) {
  const src = v2.source;
  return v2.type === "image" && typeof src === "object" && src !== null && typeof src.data === "string";
}
function namesEnvFile(obj) {
  if (!obj || typeof obj !== "object") return false;
  return [obj.filePath, obj.file_path].some(
    (p2) => typeof p2 === "string" && ENV_PATH.test(p2)
  );
}
function aboutEnvFile(obj) {
  const result = obj.toolUseResult;
  return namesEnvFile(obj) || namesEnvFile(result) || namesEnvFile(result?.file);
}
function withoutOutput(block, counts, home, envFile, errors) {
  const { content, ...rest } = block;
  const text = outputText(content);
  const out = {};
  for (const [k2, v2] of Object.entries(rest)) out[k2] = redactValue(v2, counts, home, envFile, errors);
  if (text.startsWith(INTERRUPT_MARKER)) out.content = INTERRUPT_MARKER;
  else if (block.is_error === true) {
    const { lines, picked } = errorLines(scrubText(text.replace(ANSI, ""), counts, home, envFile));
    out.content = messageFrom(lines, picked);
    if (errors && typeof block.tool_use_id === "string" && lines.length) {
      errors.push(candidateOf(block.tool_use_id, lines, picked));
    }
  } else out.content = "";
  return out;
}
function redactValue(value, counts, home, envFile = false, errors) {
  if (typeof value === "string") return scrubText(value, counts, home, envFile);
  if (Array.isArray(value))
    return value.map((v2) => redactValue(v2, counts, home, envFile, errors));
  if (typeof value !== "object" || value === null) return value;
  const obj = value;
  if (obj.type === "tool_result") return withoutOutput(obj, counts, home, envFile, errors);
  if (isImageBlock(obj)) {
    bump(counts, "image");
    const source = obj.source;
    return { ...obj, source: { ...source, data: "<image omitted>" } };
  }
  const env = envFile || aboutEnvFile(obj);
  const out = {};
  for (const [k2, v2] of Object.entries(obj)) {
    if (k2 === "toolUseResult") continue;
    const key = scrubText(k2, counts, home);
    if (SECRET_KEY.test(k2) && (typeof v2 === "string" || typeof v2 === "number") && !String(v2).startsWith("<")) {
      bump(counts, "secret-key");
      out[key] = "<REDACTED>";
    } else {
      out[key] = redactValue(v2, counts, home, env, errors);
    }
  }
  return out;
}
function redactLine(line, counts, home, errors) {
  if (!line.trim()) return void 0;
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    bump(counts, "unparsable-line");
    return void 0;
  }
  return JSON.stringify(redactValue(parsed, counts, home, false, errors));
}
function redactJson(text, counts, home) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    bump(counts, "unparsable-file");
    return "{}";
  }
  return JSON.stringify(redactValue(parsed, counts, home));
}

// cli/src/preview.ts
var PREVIEW_META = "preview.json";
var REPORT_FILE = "REDACTION_REPORT.md";
var ERROR_CANDIDATES = "error-candidates.json";
var MAX_CANDIDATES = 200;
var add = (into, from) => {
  for (const [k2, v2] of Object.entries(from)) into[k2] = (into[k2] ?? 0) + v2;
};
async function redactJsonlFile(src, dst, counts, home, errors) {
  let bytes = 0;
  await pipeline(
    createReadStream2(src, "utf8"),
    async function* (input) {
      for await (const line of createInterface2({
        input,
        crlfDelay: Infinity
      })) {
        const redacted = redactLine(line, counts, home, errors);
        if (redacted === void 0) continue;
        const chunk = `${redacted}
`;
        bytes += Buffer.byteLength(chunk);
        yield chunk;
      }
    },
    createWriteStream(dst, { mode: 384 })
  );
  return bytes;
}
async function redactFile(src, dst, counts, home, errors) {
  await mkdir2(dirname(dst), { recursive: true, mode: 448 });
  if (src.endsWith(".jsonl")) return redactJsonlFile(src, dst, counts, home, errors);
  const body = redactJson(await readFile2(src, "utf8"), counts, home);
  await writeFile2(dst, body, { mode: 384 });
  return Buffer.byteLength(body);
}
async function ensureIgnored(revefiDir) {
  await mkdir2(revefiDir, { recursive: true, mode: 448 });
  await writeFile2(join4(revefiDir, ".gitignore"), "*\n", { flag: "wx" }).catch(
    (err) => {
      if (err.code !== "EEXIST") throw err;
    }
  );
}
function uploadPath(projectsDir, file, home) {
  const [root, project, ...rest] = archivePath(projectsDir, file).split("/");
  return [root, aliasProjectDir(project ?? "", home), ...rest].join("/");
}
async function previewSession(dir, s3, opts, candidates) {
  const counts = {};
  const paths = [];
  let bytes = 0;
  for (const file of s3.files) {
    const path = uploadPath(opts.projectsDir, file, opts.home);
    const errors = [];
    bytes += await redactFile(
      file,
      join4(dir, ...path.split("/")),
      counts,
      opts.home,
      errors
    );
    candidates.push(...errors.map((c) => ({ ...c, file: path })));
    paths.push(path);
  }
  return {
    project: aliasProjectDir(s3.project, opts.home),
    id: s3.id,
    day: s3.day,
    paths,
    bytes,
    counts
  };
}
async function writePreview(opts) {
  await ensureIgnored(opts.revefiDir);
  const base = join4(opts.revefiDir, "upload-preview");
  await mkdir2(base, { recursive: true, mode: 448 });
  const stamp = (opts.now ?? /* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-");
  const dir = await mkdtemp(join4(base, `${stamp}-`));
  try {
    const meta = {
      window: opts.window,
      sessions: [],
      counts: {},
      bytes: 0
    };
    const candidates = [];
    for (const s3 of opts.sessions) {
      let ps2;
      const found = [];
      try {
        ps2 = await previewSession(dir, s3, opts, found);
      } catch (err) {
        if (err.code !== "ENOENT") throw err;
        await rm2(
          join4(
            dir,
            "projects",
            aliasProjectDir(s3.project, opts.home),
            `${s3.id}.jsonl`
          ),
          { force: true }
        );
        await rm2(
          join4(dir, "projects", aliasProjectDir(s3.project, opts.home), s3.id),
          { recursive: true, force: true }
        );
        continue;
      }
      meta.sessions.push(ps2);
      add(meta.counts, ps2.counts);
      meta.bytes += ps2.bytes;
      candidates.push(...found);
    }
    if (candidates.length) {
      meta.error_messages = { failed: candidates.length, picked_by_model: 0 };
      await writeFile2(
        join4(dir, ERROR_CANDIDATES),
        `${JSON.stringify({ candidates: candidates.slice(0, MAX_CANDIDATES) })}
`,
        { mode: 384 }
      );
    }
    await writeFile2(
      join4(dir, PREVIEW_META),
      `${JSON.stringify(meta, null, 2)}
`,
      { mode: 384 }
    );
    await writeFile2(join4(dir, REPORT_FILE), renderReport(meta), {
      mode: 384
    });
    return { dir, meta };
  } catch (err) {
    await rm2(dir, { recursive: true, force: true });
    throw err;
  }
}
var PreviewError = class extends Error {
};
var SAFE_PATH = /^projects\/(?:[^/\\:]+\/)+[^/\\:]+$/;
function safePath(p2) {
  return typeof p2 === "string" && SAFE_PATH.test(p2) && !p2.split("/").some((seg) => seg === ".." || seg === ".");
}
async function readPreview(dir) {
  const file = join4(dir, PREVIEW_META);
  let text;
  try {
    text = await readFile2(file, "utf8");
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
    throw new PreviewError(`No preview at ${dir}. Previews are removed once uploaded; run \`prepare\` to make a new one.`);
  }
  let meta;
  try {
    meta = JSON.parse(text);
  } catch {
    throw new PreviewError(`${file} is damaged. Run \`prepare\` again.`);
  }
  const valid = meta.window !== void 0 && Array.isArray(meta.sessions) && meta.sessions.every((s3) => Array.isArray(s3.paths) && s3.paths.every(safePath));
  if (!valid) throw new PreviewError(`${file} is not a preview this CLI wrote. Run \`prepare\` again.`);
  return meta;
}
function humanSize(bytes) {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}
var RULE_LABELS = {
  "private-key": "Private key blocks",
  "anthropic-key": "Anthropic API keys",
  "openai-key": "OpenAI API keys",
  "github-token": "GitHub tokens",
  "aws-access-key": "AWS access key IDs",
  "slack-token": "Slack tokens",
  "stripe-key": "Stripe keys",
  "google-api-key": "Google API keys",
  jwt: "JSON Web Tokens",
  "bearer-token": "Bearer tokens",
  "url-credentials": "Passwords in URLs",
  "secret-assignment": "Values assigned to password / secret / token / key names",
  "env-file": ".env file bodies (every value masked)",
  "base64-blob": "Long base64 blobs",
  image: "Images",
  email: "Email addresses",
  phone: "Phone numbers",
  "card-number": "Payment card numbers",
  iban: "Bank account numbers (IBAN)",
  ssn: "US Social Security numbers",
  "national-id": "National ID and tax numbers (Aadhaar, PAN, UK NI, Canadian SIN)",
  "upi-id": "UPI payment IDs",
  "ip-address": "IP addresses outside private ranges",
  "home-path": "Your home folder path (shown as ~)",
  username: "Your username elsewhere, like build caches and folder names (shown as {USER})",
  "unparsable-line": "Incomplete lines (dropped)",
  "unparsable-file": "Unreadable metadata files (emptied)"
};
var cell = (s3) => s3.replace(/[|`]/g, (c) => `\\${c}`);
function errorMessagesLine({ failed, picked_by_model: picked }) {
  const calls = `${failed} tool call${failed === 1 ? "" : "s"} failed`;
  const each = `${calls}. Each sends only its error message`;
  if (!picked) return `${each}: a few lines picked by a fixed rule.`;
  const haiku = "Claude Haiku in your Claude Code session chose which lines state the error";
  return picked >= failed ? `${each}; ${haiku}.` : `${each}. For ${picked}, ${haiku}; the rest use a fixed rule.`;
}
function renderReport(meta) {
  const rows = Object.entries(meta.counts).sort(([, a], [, b2]) => b2 - a).map(([id, n]) => `| ${RULE_LABELS[id] ?? id} | ${n} |`);
  const sessions = [...meta.sessions].sort((a, b2) => b2.bytes - a.bytes).map(
    (s3) => `| ${humanSize(s3.bytes)} | ${cell(s3.day)} | ${cell(s3.project)} | ${cell(s3.id)} | ${Object.values(s3.counts).reduce((a, b2) => a + b2, 0)} |`
  );
  return [
    "# What will be uploaded",
    "",
    `${meta.sessions.length} Claude Code sessions that started between ${meta.window.start} and ${meta.window.end}, ${humanSize(meta.bytes)} after redaction. The \`projects/\` folder next to this file holds exactly the files that will be sent, plus a summary of their sizes and dates.`,
    "",
    "## Sent as written",
    "",
    "Your prompts, Claude's replies, the commands it ran and the code it wrote are uploaded as they are. The output of tools is not: a call that failed keeps only its error message, a few lines at most. Redaction removes the known secret and personal-data formats listed below; it cannot recognise every kind of sensitive text. Read through the files if a session touched something you would not share.",
    "",
    "## Removed on this machine",
    "",
    ...rows.length ? ["| What | Replaced |", "| --- | --- |", ...rows] : [
      "No known secret formats were found. Everything else is still sent as written."
    ],
    "",
    "Tool output that Claude Code saves outside the transcripts (`tool-results/`) is never uploaded.",
    "",
    ...meta.error_messages ? [errorMessagesLine(meta.error_messages), ""] : [],
    "## Sessions, largest first",
    "",
    "| Size | Started | Project | Session | Redactions |",
    "| --- | --- | --- | --- | --- |",
    ...sessions,
    "",
    "What is in this folder is what is sent. To leave a session out, run the analysis again with `--exclude-session <session>` rather than deleting files here, which stops the upload.",
    ""
  ].join("\n");
}

// cli/src/pack.ts
var LIMITS = {
  maxDays: 7,
  maxCompressedBytes: 200 * 1024 * 1024,
  maxUncompressedBytes: 2 * 1024 * 1024 * 1024
};
async function pack(previewDir, meta, outFile) {
  const root = await realpath(previewDir);
  const paths = meta.sessions.flatMap((s3) => s3.paths);
  for (const p2 of paths) await assertInside(root, p2);
  let uncompressed = 0;
  await Qn(
    {
      gzip: true,
      portable: true,
      noMtime: true,
      cwd: root,
      file: outFile,
      mode: 384,
      filter: (_path, st2) => {
        if (!("isFile" in st2) || !st2.isFile()) return false;
        uncompressed += st2.size;
        return true;
      }
    },
    paths
  );
  return { compressed: (await stat3(outFile)).size, uncompressed };
}
async function assertInside(root, path) {
  let real;
  try {
    real = await realpath(join5(root, ...path.split("/")));
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
    throw new PreviewError(
      `${path} was removed from the preview, so nothing was uploaded. Run \`prepare\` again; to leave a session out, use --exclude-session.`
    );
  }
  if (!real.startsWith(root + sep2)) {
    throw new PreviewError(`${path} points outside the preview folder, so nothing was uploaded. Run \`prepare\` again.`);
  }
}
function buildManifest(meta, packed, client2) {
  return {
    format_version: 1,
    tool: "claude-code",
    client: client2,
    window: meta.window,
    session_count: meta.sessions.length,
    bytes: { compressed: packed.compressed, uncompressed: packed.uncompressed }
  };
}
function limitProblem(m2) {
  if (m2.window.days > LIMITS.maxDays) {
    return `The window is ${m2.window.days} days; the most you can analyze at once is ${LIMITS.maxDays}. Use --days ${LIMITS.maxDays} or fewer.`;
  }
  if (m2.session_count === 0) {
    const longer = m2.window.days < LIMITS.maxDays ? ` or --days ${LIMITS.maxDays}` : "";
    return `No Claude Code sessions started between ${m2.window.start} and ${m2.window.end} here. Try --all-projects${longer}.`;
  }
  const over = m2.bytes.compressed > LIMITS.maxCompressedBytes ? `${humanSize(m2.bytes.compressed)} compressed; the limit is ${humanSize(LIMITS.maxCompressedBytes)}` : m2.bytes.uncompressed > LIMITS.maxUncompressedBytes ? `${humanSize(m2.bytes.uncompressed)} before compression; the limit is ${humanSize(LIMITS.maxUncompressedBytes)}` : void 0;
  if (over) {
    return `The upload is ${over}. Use a shorter --days, or leave out the largest sessions (listed first in REDACTION_REPORT.md) with --exclude-session.`;
  }
  return void 0;
}

// cli/src/errorpick.ts
import { readFile as readFile3, writeFile as writeFile3 } from "node:fs/promises";
import { join as join6 } from "node:path";
function parsePicks(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PreviewError(`The picks aren't JSON. Expected {"<tool_use_id>": [line numbers]}.`);
  }
  const ok = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) && Object.values(parsed).every((v2) => Array.isArray(v2) && v2.every((n) => Number.isInteger(n)));
  if (!ok) throw new PreviewError('Expected {"<tool_use_id>": [line numbers]}, with whole numbers only.');
  return parsed;
}
async function readCandidates(dir) {
  let text;
  try {
    text = await readFile3(join6(dir, ERROR_CANDIDATES), "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
  const parsed = JSON.parse(text);
  return Array.isArray(parsed.candidates) ? parsed.candidates : [];
}
function rewrite(text, chosen) {
  let changed = 0;
  const lines = text.split("\n").map((line) => {
    if (!line) return line;
    const rec = JSON.parse(line);
    const content = rec.message?.content;
    if (!Array.isArray(content)) return line;
    let hit = false;
    for (const block of content) {
      const id = block?.tool_use_id;
      if (block?.type === "tool_result" && block.is_error === true && typeof id === "string" && chosen.has(id)) {
        block.content = chosen.get(id);
        hit = true;
        changed++;
      }
    }
    return hit ? JSON.stringify(rec) : line;
  });
  return { text: lines.join("\n"), changed };
}
async function applyErrorPicks(dir, picks) {
  const meta = await readPreview(dir);
  const candidates = await readCandidates(dir);
  const byId = new Map(candidates.map((c) => [c.id, c]));
  const chosen = /* @__PURE__ */ new Map();
  const ignored = [];
  for (const [id, numbers] of Object.entries(picks)) {
    const c = byId.get(id);
    const indexes = c ? numbers.filter((n) => n >= 1 && n <= c.lines.length).map((n) => n - 1) : [];
    const message = c && indexes.length ? messageFrom(c.lines, indexes) : "";
    if (message) chosen.set(id, message);
    else ignored.push(id);
  }
  const files = new Set([...chosen.keys()].map((id) => byId.get(id)?.file ?? ""));
  let applied = 0;
  for (const session of meta.sessions) {
    for (const file of session.paths.filter((p2) => files.has(p2))) {
      const path = join6(dir, ...file.split("/"));
      const before = await readFile3(path, "utf8");
      const { text, changed } = rewrite(before, chosen);
      if (!changed) continue;
      await writeFile3(path, text, { mode: 384 });
      const delta = Buffer.byteLength(text) - Buffer.byteLength(before);
      session.bytes += delta;
      meta.bytes += delta;
      applied += changed;
    }
  }
  meta.error_messages = { failed: meta.error_messages?.failed ?? candidates.length, picked_by_model: applied };
  await writeFile3(join6(dir, PREVIEW_META), `${JSON.stringify(meta, null, 2)}
`, { mode: 384 });
  await writeFile3(join6(dir, REPORT_FILE), renderReport(meta), { mode: 384 });
  return { applied, ignored };
}

// cli/src/commands.ts
var UsageError = class extends Error {
};
var UserError = class extends Error {
};
var STILL_RUNNING = 3;
var SCOPE_OPTIONS = {
  days: { type: "string" },
  "all-projects": { type: "boolean" },
  "exclude-session": { type: "string", multiple: true }
};
var API_OPTION = { api: { type: "string" } };
function parse(args, options, positionals = 0) {
  let parsed;
  try {
    parsed = parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (e) {
    throw new UsageError(e.message);
  }
  if (parsed.positionals.length !== positionals) {
    throw new UsageError(
      positionals === 0 ? `Unexpected argument: ${parsed.positionals[0]}` : `Expected ${positionals} argument${positionals > 1 ? "s" : ""}, got ${parsed.positionals.length}.`
    );
  }
  return parsed;
}
function projectRoot(cwd) {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return cwd;
  }
}
function apiBase(e, api) {
  const raw = api ?? e.env.REVEFI_ANALYZER_API ?? DEFAULT_API;
  let url;
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
function serverDir(e, base) {
  const root = e.configDir ?? configDir(e.env);
  const host = new URL(base).host;
  return host === new URL(DEFAULT_API).host ? root : join7(root, "servers", host.replace(/[^\w.-]/g, "_"));
}
var loginCommand = (api) => `revefi-agent-analyzer login${api ? ` --api ${quote(api)}` : ""}`;
function auth(e, api) {
  const base = apiBase(e, api);
  return new Auth({ base, dir: serverDir(e, base), fetch: e.fetch, sleep: e.sleep, env: e.env, loginCommand: loginCommand(api) });
}
function openInBrowser(url) {
  if (process.platform === "linux" && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) return;
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", url]] : ["xdg-open", [url]];
  const child = spawn(cmd, args, { stdio: "ignore", detached: true, windowsHide: true });
  child.on("error", () => void 0);
  child.unref();
}
function describeLogin(e, p2) {
  e.io.err(`Open this link to sign in:
  ${p2.verification_uri_complete}`);
  e.io.err(`Check that the page shows the code ${p2.user_code}, then continue with Google or an emailed code.`);
}
function client(e, api, a = auth(e, api)) {
  return new Client({
    base: apiBase(e, api),
    token: (force) => a.accessToken(force),
    loginCommand: loginCommand(api),
    userAgent: `revefi-agent-analyzer/${e.version}`,
    fetch: e.fetch,
    sleep: e.sleep,
    env: e.env
  });
}
async function signIn(e, a, openBrowser, timeoutMs) {
  const pending = await a.startLogin();
  describeLogin(e, pending);
  if (openBrowser) (e.openUrl ?? openInBrowser)(pending.verification_uri_complete);
  return (await a.finishLogin({ timeoutMs })).email;
}
async function ensureSignedIn(e, a) {
  try {
    await a.accessToken();
    return;
  } catch (err) {
    if (!(err instanceof SignInError) || err.reason !== "signed_out" || !e.isTTY) throw err;
  }
  const email = await signIn(e, a, true);
  e.io.err(email ? `Signed in as ${email}.` : "Signed in.");
}
function wholeNumber(raw, flag, fallback, min, max = Number.MAX_SAFE_INTEGER) {
  if (raw === void 0) return fallback;
  const n = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!(n >= min && n <= max)) {
    throw new UsageError(max === Number.MAX_SAFE_INTEGER ? `${flag} must be a whole number of at least ${min}.` : `${flag} must be a whole number from ${min} to ${max}.`);
  }
  return n;
}
var quote = (p2) => /^[\w./~-]+$/.test(p2) ? p2 : `"${p2.replace(/(["\\$`])/g, "\\$1")}"`;
var COUNT_LABELS = {
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
  "ip-address": ["IP address", "IP addresses"]
};
function redactionLine(meta) {
  const named = Object.entries(meta.counts).filter(([id]) => COUNT_LABELS[id]);
  const other = Object.entries(meta.counts).filter(([id]) => !COUNT_LABELS[id] && id !== "home-path" && id !== "username" && !id.startsWith("unparsable")).reduce((a, [, n]) => a + n, 0);
  const parts = named.sort(([, a], [, b2]) => b2 - a).map(([id, n]) => `${n} ${COUNT_LABELS[id]?.[n === 1 ? 0 : 1]}`);
  if (other) parts.push(`${other} other secret${other === 1 ? "" : "s"} or blobs`);
  return parts.length ? `Removed: ${parts.join(", ")}` : "No known secrets or personal data found.";
}
var UPLOAD_TO = "upload_to";
async function checkHost(dir, base) {
  const file = join7(dir, UPLOAD_TO);
  const recorded = existsSync(file) ? (await readFile4(file, "utf8")).trim() : "";
  const host = new URL(base).host;
  if (recorded && canonicalHost(recorded) !== canonicalHost(host)) {
    throw new UserError(`This preview was prepared for ${recorded}, not ${host}. Run \`prepare\` again for ${host}, or pass --api for ${recorded}.`);
  }
}
async function prepareFrom(e, values) {
  const days = wholeNumber(values.days, "--days", LIMITS.maxDays, 1, LIMITS.maxDays);
  const root = projectRoot(e.cwd);
  const projectsDir = defaultProjectsDir(e.env);
  const all = Boolean(values["all-projects"]);
  const { window, sessions } = await collect({
    projectsDir,
    root: all ? void 0 : root,
    days,
    today: utcToday(),
    exclude: values["exclude-session"]
  });
  const empty = limitProblem({ window, session_count: sessions.length, bytes: { compressed: 0, uncompressed: 0 } });
  if (empty) throw new UserError(empty);
  const { dir, meta } = await writePreview({ projectsDir, window, sessions, revefiDir: join7(root, ".revefi"), home: homedir3() });
  await writeFile4(join7(dir, UPLOAD_TO), `${new URL(apiBase(e, values.api)).host}
`, { mode: 384 });
  return { dir, meta, sourceBytes: sessions.reduce((a, s3) => a + s3.bytes, 0), scope: all ? "all projects on this machine" : root };
}
function describePreview(e, p2, api) {
  const { meta } = p2;
  const size = p2.sourceBytes === void 0 ? humanSize(meta.bytes) : `${humanSize(p2.sourceBytes)} \u2192 ${humanSize(meta.bytes)} after redaction`;
  const projects = new Set(meta.sessions.map((s3) => s3.project)).size;
  if (p2.scope) e.io.out(`Scope: ${p2.scope}`);
  e.io.out(`${meta.sessions.length} sessions in ${projects} project${projects === 1 ? "" : "s"}, ${meta.window.start} to ${meta.window.end} \xB7 ${size}`);
  e.io.out(redactionLine(meta));
  e.io.out(`Preview: ${relative2(e.cwd, p2.dir) || "."}  (${REPORT_FILE} there lists exactly what is sent)`);
  e.io.out("");
  e.io.out(`This uploads the redacted transcripts in the preview to ${new URL(api).host} for analysis.`);
}
async function consent(e, values, dir) {
  if (values.yes) return true;
  if (values.json || !e.isTTY) {
    e.io.err(
      `Nothing was uploaded: there is no terminal here to confirm it. Review ${quote(join7(relative2(e.cwd, dir) || ".", REPORT_FILE))}, then run \`revefi-agent-analyzer upload ${quote(relative2(e.cwd, dir) || ".")}\` in a terminal.`
    );
    return false;
  }
  if (await e.ask("Upload? [y/N] ")) return true;
  e.io.err(`Nothing was uploaded. The preview stays in ${quote(relative2(e.cwd, dir) || ".")} until you delete it.`);
  return false;
}
function clientName(e) {
  return e.env.CLAUDECODE ? "plugin" : "cli";
}
function isPreviewFolder(dir) {
  return basename(dirname2(dir)) === "upload-preview" && basename(dirname2(dirname2(dir))) === ".revefi";
}
async function uploadPreview(e, dir, api, a = auth(e, api)) {
  const meta = await readPreview(dir);
  await checkHost(dir, apiBase(e, api));
  await ensureSignedIn(e, a);
  const archive = join7(dir, "upload.tar.gz");
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
    if (isPreviewFolder(dir)) await rm3(dir, { recursive: true, force: true });
    return { c, runId: run.run_id, reportUrl, status };
  } finally {
    await rm3(archive, { force: true });
  }
}
var PHASE_COPY = {
  uploading: "Waiting for the upload",
  analyzing: "Analyzing",
  finishing: "Building the report"
};
var usd = (n) => `$${n >= 100 ? Math.round(n).toLocaleString("en-US") : n.toFixed(2)}`;
function topRecommendations(recs, n = 3) {
  return recs.recommendations.filter((r) => r.verdict === "optimizable").sort((a, b2) => b2.cluster.window_usd - a.cluster.window_usd).slice(0, n);
}
function printSummary(e, recs) {
  const optimizable = recs.recommendations.filter((r) => r.verdict === "optimizable");
  if (optimizable.length === 0) {
    e.io.out("No repeated tasks worth fixing were found in this window.");
    return;
  }
  const total = optimizable.reduce((a, r) => a + r.cluster.window_usd, 0);
  e.io.out(`\u2248 ${usd(total)} went to ${optimizable.length} repeated tasks in this window (at API pricing).`);
  topRecommendations(recs).forEach((r, i) => e.io.out(`  ${i + 1}. ${r.title}  \u2248 ${usd(r.cluster.window_usd)}  (${r.id})`));
}
function runJson(runId, reportUrl, s3, recs) {
  return JSON.stringify({
    run_id: runId,
    report_url: reportUrl,
    phase: s3.phase,
    percent: s3.percent,
    cost_capped: s3.cost_capped,
    top: recs ? topRecommendations(recs) : []
  });
}
function finish(e, s3, runId) {
  if (s3.phase === "done") return 0;
  if (s3.phase === "deferred") {
    e.io.err("The analyzer is at capacity and deferred this run. Try again tomorrow.");
    return 1;
  }
  if (s3.phase === "failed") {
    e.io.err(`The analysis failed on the server. Try again; if it fails again, report run ${runId} at ${ISSUES_URL}.`);
    return 1;
  }
  e.io.err(`Still ${(PHASE_COPY[s3.phase] ?? s3.phase).toLowerCase()} (${s3.percent}%). Check later with:
  revefi-agent-analyzer status ${runId} --wait`);
  return STILL_RUNNING;
}
async function follow(e, run, timeoutSec, json) {
  let s3;
  let recs;
  try {
    let last = "";
    s3 = await run.c.waitForRun(run.runId, {
      timeoutMs: timeoutSec * 1e3,
      onProgress: (st2) => {
        const line = `${PHASE_COPY[st2.phase] ?? st2.phase}... ${st2.percent}%`;
        if (line !== last && !FINAL_PHASES.includes(st2.phase)) e.io.err(line);
        last = line;
      }
    });
    recs = s3.phase === "done" ? await run.c.recommendations(run.runId) : void 0;
  } catch (err) {
    throw new UserError(`${err.message}
The run was started; check it later with: revefi-agent-analyzer status ${run.runId} --wait`);
  }
  if (json) {
    e.io.out(runJson(run.runId, run.reportUrl, s3, recs));
    return finish(e, s3, run.runId);
  }
  e.io.out("");
  e.io.out(`Report: ${run.reportUrl}`);
  if (s3.cost_capped) e.io.out("The analyzer hit today's analysis limit partway through, so parts of the report may be missing. Run again tomorrow for a full report.");
  if (recs) printSummary(e, recs);
  e.io.out(`Run id: ${run.runId}  (for status, share, feedback)`);
  return finish(e, s3, run.runId);
}
var COMMANDS = {
  login: {
    summary: "Sign in with Google or an emailed code (--start and --wait split it in two, for scripts)",
    async run(args, e) {
      const { values } = parse(args, {
        ...API_OPTION,
        start: { type: "boolean" },
        wait: { type: "boolean" },
        json: { type: "boolean" },
        "no-browser": { type: "boolean" },
        timeout: { type: "string" }
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
              expires_in: Math.round((pending.expires_at - Date.now()) / 1e3)
            })
          );
        } else {
          describeLogin(e, pending);
          e.io.err(`Then run: ${loginCommand(values.api)} --wait`);
        }
        return 0;
      }
      const timeout = values.timeout === void 0 ? void 0 : wholeNumber(values.timeout, "--timeout", 0, 1) * 1e3;
      const email = values.wait ? (await a.finishLogin({ timeoutMs: timeout })).email : await signIn(e, a, e.isTTY && !values["no-browser"], timeout);
      if (values.json) e.io.out(JSON.stringify({ email }));
      else e.io.out(email ? `Signed in as ${email}.` : "Signed in.");
      return 0;
    }
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
    }
  },
  whoami: {
    summary: "Show who you're signed in as",
    async run(args, e) {
      const { values } = parse(args, { ...API_OPTION, json: { type: "boolean" } });
      const email = await auth(e, values.api).email();
      e.io.out(values.json ? JSON.stringify({ email }) : email ? `Signed in as ${email}.` : "Signed in (email unavailable).");
      return 0;
    }
  },
  analyze: {
    summary: "Collect, redact, preview, upload and wait for the report (asks before uploading)",
    async run(args, e) {
      const { values } = parse(args, { ...SCOPE_OPTIONS, ...API_OPTION, yes: { type: "boolean", short: "y" }, timeout: { type: "string" } });
      const timeout = wholeNumber(values.timeout, "--timeout", 30 * 60, 0);
      const api = apiBase(e, values.api);
      const a = auth(e, values.api);
      if (e.isTTY) await ensureSignedIn(e, a);
      const p2 = await prepareFrom(e, values);
      describePreview(e, p2, api);
      if (!await consent(e, values, p2.dir)) return 1;
      return follow(e, await uploadPreview(e, p2.dir, values.api, a), timeout, false);
    }
  },
  prepare: {
    summary: "Collect and redact sessions into a local preview folder; uploads nothing",
    async run(args, e) {
      const { values } = parse(args, { ...SCOPE_OPTIONS, ...API_OPTION, json: { type: "boolean" } });
      const api = apiBase(e, values.api);
      const p2 = await prepareFrom(e, values);
      if (values.json) {
        e.io.out(
          JSON.stringify({
            preview_dir: p2.dir,
            report: join7(p2.dir, REPORT_FILE),
            scope: p2.scope,
            window: p2.meta.window,
            sessions: p2.meta.sessions.length,
            session_list: p2.meta.sessions.map((s3) => ({ id: s3.id, project: s3.project, day: s3.day, bytes: s3.bytes })),
            bytes_before: p2.sourceBytes,
            bytes_after: p2.meta.bytes,
            redactions: p2.meta.counts,
            failed_tool_calls: p2.meta.error_messages?.failed ?? 0,
            error_candidates: p2.meta.error_messages ? join7(p2.dir, ERROR_CANDIDATES) : null,
            upload_to: new URL(api).host
          })
        );
      } else {
        describePreview(e, p2, api);
        e.io.out(`Upload it with: revefi-agent-analyzer upload ${quote(relative2(e.cwd, p2.dir))}`);
      }
      return 0;
    }
  },
  "pick-errors": {
    summary: "Use the chosen lines as failed calls' error messages in a preview (the plugin's Haiku step)",
    async run(args, e) {
      const { values, positionals } = parse(args, { picks: { type: "string" }, json: { type: "boolean" } }, 1);
      if (!values.picks) throw new UsageError("pick-errors needs --picks '<json>'.");
      const r = await applyErrorPicks(resolve(e.cwd, positionals[0] ?? ""), parsePicks(values.picks));
      e.io.out(
        values.json ? JSON.stringify(r) : `Used the chosen lines for ${r.applied} error message${r.applied === 1 ? "" : "s"}${r.ignored.length ? `; ignored ${r.ignored.length}` : ""}.`
      );
      return 0;
    }
  },
  upload: {
    summary: "Upload a prepared preview folder and wait for the report",
    async run(args, e) {
      const { values, positionals } = parse(
        args,
        { ...API_OPTION, yes: { type: "boolean", short: "y" }, json: { type: "boolean" }, "no-wait": { type: "boolean" }, timeout: { type: "string" } },
        1
      );
      const timeout = wholeNumber(values.timeout, "--timeout", 480, 0);
      const api = apiBase(e, values.api);
      const dir = resolve(e.cwd, positionals[0] ?? "");
      const meta = await readPreview(dir);
      if (!values.json) describePreview(e, { dir, meta }, api);
      if (!await consent(e, values, dir)) return 1;
      const run = await uploadPreview(e, dir, values.api);
      if (values["no-wait"]) {
        if (values.json) e.io.out(runJson(run.runId, run.reportUrl, run.status));
        else e.io.out(`Follow it with: revefi-agent-analyzer status ${run.runId} --wait`);
        return 0;
      }
      return follow(e, run, timeout, Boolean(values.json));
    }
  },
  status: {
    summary: "Show a run's progress; --wait follows it until the report is ready",
    async run(args, e) {
      const { values, positionals } = parse(args, { ...API_OPTION, wait: { type: "boolean" }, json: { type: "boolean" }, timeout: { type: "string" } }, 1);
      const timeout = wholeNumber(values.timeout, "--timeout", 480, 0);
      const runId = positionals[0] ?? "";
      const c = client(e, values.api);
      const s3 = await c.status(runId);
      const reportUrl = c.link(s3.report_url);
      if (values.wait) return follow(e, { c, runId, reportUrl }, timeout, Boolean(values.json));
      e.io.out(values.json ? runJson(runId, reportUrl, s3) : `${PHASE_COPY[s3.phase] ?? s3.phase} ${s3.percent}%  ${reportUrl}`);
      return 0;
    }
  },
  recommendations: {
    summary: "Print a finished run's recommendations (--json for the full list)",
    async run(args, e) {
      const { values, positionals } = parse(args, { ...API_OPTION, json: { type: "boolean" } }, 1);
      const recs = await client(e, values.api).recommendations(positionals[0] ?? "");
      if (values.json) e.io.out(JSON.stringify(recs));
      else printSummary(e, recs);
      return 0;
    }
  },
  feedback: {
    summary: "Rate a recommendation: feedback <run> <recommendation> up|down [--applied-pr URL]",
    async run(args, e) {
      const { values, positionals } = parse(args, { ...API_OPTION, "applied-pr": { type: "string" } }, 3);
      const [runId = "", recId = "", verdict = ""] = positionals;
      if (verdict !== "up" && verdict !== "down") throw new UsageError("The rating must be up or down.");
      const pr2 = values["applied-pr"];
      await client(e, values.api).feedback(runId, recId, pr2 ? { verdict, source: "skill", applied_pr_url: pr2 } : { verdict, source: "user" });
      e.io.out(pr2 ? "Recorded the applied fix. Thanks." : "Thanks, your rating was recorded.");
      return 0;
    }
  },
  share: {
    summary: "Show or change who can open a run's report: share <run> [--add EMAIL] [--remove EMAIL] [--link on|off]",
    async run(args, e) {
      const { values, positionals } = parse(
        args,
        { ...API_OPTION, add: { type: "string", multiple: true }, remove: { type: "string", multiple: true }, link: { type: "string" }, json: { type: "boolean" } },
        1
      );
      const runId = positionals[0] ?? "";
      if (values.link !== void 0 && values.link !== "on" && values.link !== "off") {
        throw new UsageError("--link must be on (anyone signed in with the link) or off.");
      }
      const add2 = (values.add ?? []).map((email) => email.trim().toLowerCase());
      const bad = add2.find((email) => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email));
      if (bad) throw new UsageError(`${bad} isn't an email address.`);
      const c = client(e, values.api);
      let sharing = await c.sharing(runId);
      const remove = new Set((values.remove ?? []).map((email) => email.trim().toLowerCase()));
      const next = {
        link: values.link === void 0 ? sharing.link : values.link === "on",
        emails: [.../* @__PURE__ */ new Set([...sharing.emails, ...add2])].filter((email) => !remove.has(email))
      };
      if (add2.length || remove.size || values.link !== void 0) sharing = await c.setSharing(runId, next);
      const { report_url } = await c.status(runId);
      if (values.json) {
        e.io.out(JSON.stringify({ ...sharing, report_url: c.link(report_url) }));
        return 0;
      }
      e.io.out(sharing.emails.length ? `Shared with: ${sharing.emails.join(", ")}` : "Not shared with anyone by email.");
      e.io.out(sharing.link ? "Anyone signed in who has the link can open it." : "The link alone doesn't give access.");
      e.io.out(`Report: ${c.link(report_url)}`);
      return 0;
    }
  },
  "delete-my-data": {
    summary: "Delete every run, upload and report made with your account",
    async run(args, e) {
      const { values } = parse(args, { ...API_OPTION, yes: { type: "boolean", short: "y" } });
      const a = auth(e, values.api);
      const email = await a.email() ?? "your account";
      if (!values.yes) {
        if (!e.isTTY) {
          e.io.err(`Nothing was deleted. Run again with --yes to delete every run, upload and report made with ${email}.`);
          return 1;
        }
        if (!await e.ask(`Delete every run, upload and report made with ${email}? This can't be undone. [y/N] `)) {
          e.io.err("Nothing was deleted.");
          return 1;
        }
      }
      await client(e, values.api, a).deleteMyData();
      e.io.out(`Deleted every run, upload and report made with ${email}. Local previews in .revefi/ are untouched.`);
      return 0;
    }
  }
};
async function askYesNo(question) {
  const rl = createInterface3({ input: process.stdin, output: process.stderr });
  try {
    return /^y(es)?$/i.test((await rl.question(question)).trim());
  } catch (err) {
    if (err.name === "AbortError") return false;
    throw err;
  } finally {
    rl.close();
  }
}

// cli/src/main.ts
var VERSION = true ? "0.4.1" : "0.0.0-dev";
var USAGE = `Usage: revefi-agent-analyzer <command> [options]

Find repeated work and wasted spend in your Claude Code sessions.

Commands:
${Object.entries(COMMANDS).map(([name, c]) => `  ${name.padEnd(17)}${c.summary}`).join("\n")}

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
  --api URL              Analyzer server (default REVEFI_ANALYZER_API, else optimizer.revefi.com)
  -h, --help             Show this help
  -v, --version          Show the version

A preview is a folder under .revefi/upload-preview/ holding exactly the redacted files that will
be sent. It is removed once uploaded.

Exit codes: 0 done, 1 failed or refused, 2 bad usage, 3 the analysis is still running.
Environment: CLAUDE_CONFIG_DIR (where Claude Code keeps sessions), REVEFI_ANALYZER_API,
REVEFI_DEBUG=1 (show stack traces).`;
var consoleIo = { out: console.log, err: console.error };
function defaultEnv(io2 = consoleIo) {
  return {
    io: io2,
    version: VERSION,
    cwd: process.cwd(),
    env: process.env,
    isTTY: Boolean(process.stdin.isTTY && process.stderr.isTTY),
    ask: askYesNo
  };
}
var SIGN_IN_KINDS = { signed_out: "sign_in", pending: "sign_in_pending", failed: "sign_in_failed" };
function classify(err, debug) {
  if (err instanceof UsageError) return { kind: "usage", message: err.message };
  if (err instanceof SignInError) return { kind: SIGN_IN_KINDS[err.reason], message: err.message };
  if (err instanceof ApiError) return { kind: "server", message: err.message, status: err.status };
  if (err instanceof UserError || err instanceof PreviewError) return { kind: "refused", message: err.message };
  const e = err;
  return {
    kind: "unexpected",
    message: `Something unexpected went wrong: ${debug ? e.stack : e.message}
Please report it at ${ISSUES_URL}${debug ? "" : " (set REVEFI_DEBUG=1 for details)"}.`
  };
}
async function main(argv, e = defaultEnv()) {
  const [command, ...rest] = argv;
  if (command === void 0 || command.startsWith("-")) {
    let values;
    try {
      ({ values } = parseArgs2({
        args: argv,
        options: { help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" } }
      }));
    } catch (err) {
      e.io.err(`${err.message}

${USAGE}`);
      return 2;
    }
    e.io.out(values.version ? VERSION : USAGE);
    return 0;
  }
  const cmd = COMMANDS[command];
  if (!cmd) {
    e.io.err(`Unknown command: ${command}

${USAGE}`);
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
    if (rest.includes("--json")) e.io.out(JSON.stringify({ error: { kind, message, ...status ? { status } : {} } }));
    e.io.err(kind === "usage" ? `${message}

Run \`revefi-agent-analyzer --help\` for usage.` : message);
    return kind === "usage" ? 2 : 1;
  }
}

// cli/src/bin.ts
process.exitCode = await main(process.argv.slice(2));

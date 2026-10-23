import { link, mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { unreachable } from "./net.js";

/** GET /api/auth/config: where this server's users sign in. */
export interface AuthConfig {
  domain: string;
  audience: string;
  cli_client_id: string;
}

/** What `login` keeps on disk, owner-only: enough to get a fresh access token. */
interface Credentials {
  domain: string;
  audience: string;
  client_id: string;
  refresh_token: string;
  email: string | null;
}

/** A device login waiting for the user to approve it in a browser. */
export interface PendingLogin {
  user_code: string;
  verification_uri_complete: string;
  expires_at: number;
  interval: number;
  device_code: string;
  config: AuthConfig;
}

/**
 * Signing in is needed, or failed in a way only the user can fix. `signed_out` is the only
 * reason a fresh sign-in fixes; `pending` means the user hasn't approved the started one yet.
 */
export class SignInError extends Error {
  constructor(
    message: string,
    readonly reason: "signed_out" | "pending" | "failed" = "failed",
  ) {
    super(message);
    this.name = "SignInError";
  }
}

const CREDENTIALS = "credentials.json";
// The current access token, so each CLI run doesn't renew (and rotate) the refresh token.
const ACCESS = "access-token.json";
const LOCK = "renew.lock";
const MAX_POLL_INTERVAL_S = 30;
// A bare host name: the domain is spliced into URLs that receive the refresh token.
const HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i;
const PENDING = "pending-login.json";
const TIMEOUT_MS = 30_000;
// A renewal is one request, so a lock older than a few timeouts was left by a process that died.
const STALE_LOCK_MS = 3 * TIMEOUT_MS;
// Expired access tokens are refreshed a minute early, so a slow request doesn't carry a dead one.
const EXPIRY_MARGIN_MS = 60_000;

const REFUSALS = new Map([
  ["unapproved_authentication_method", "Your organization requires its own sign-in, which the analyzer doesn't support yet."],
  ["unapproved_audience", "This sign-in can't be used for the analyzer."],
]);

export interface AuthOptions {
  /** The analyzer server, e.g. https://optimizer.revefi.com. */
  base: string;
  /** Where this server's credentials live. */
  dir: string;
  /** The command that signs in to this server, for messages. */
  loginCommand?: string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  env?: NodeJS.ProcessEnv;
}

interface CachedAccess {
  token: string;
  expires_at: number;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
}

/** The email in an ID token's payload; only displayed, so its signature isn't checked here. */
function emailFrom(idToken: string | undefined): string | null {
  const payload = idToken?.split(".")[1];
  if (!payload) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { email?: unknown };
    return typeof claims.email === "string" ? claims.email : null;
  } catch {
    return null; // A malformed ID token only costs the "Signed in as" line.
  }
}

// One server under two names: prod's Auth0 API kept the old host as its identifier.
const SERVER_ALIASES: Readonly<Record<string, string>> = { "analyzer.revefi.com": "optimizer.revefi.com" };

/** The host a server is known by, so its old name and its new one compare equal. */
export function canonicalHost(host: string): string {
  return SERVER_ALIASES[host] ?? host;
}

function sameOrigin(a: string, b: string): boolean {
  try {
    const [x, y] = [new URL(a), new URL(b)];
    return x.protocol === y.protocol && canonicalHost(x.host) === canonicalHost(y.host);
  } catch {
    return false; // An audience that isn't a URL can't belong to this server.
  }
}

function isSignInPage(link: string, domain: string): boolean {
  try {
    const url = new URL(link);
    return url.protocol === "https:" && url.host === domain && !url.username && !url.password;
  } catch {
    return false; // Not a URL at all.
  }
}

/** Replaces the file whole, so a reader in another process never sees it half-written. */
async function writePrivate(file: string, value: unknown): Promise<void> {
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(tmp, file);
}

const isMissing = (err: unknown) => (err as NodeJS.ErrnoException).code === "ENOENT";

/**
 * Moves a stale lock aside rather than deleting it: if another process broke it first and already
 * holds a new lock, that new one is what got moved, so it is put back.
 */
export async function breakStaleLock(lock: string, staleMtime: number): Promise<void> {
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
    // EEXIST: a third process locked meanwhile, and its lock stands.
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  } finally {
    await rm(moved, { force: true });
  }
}

export class Auth {
  private readonly base: string;
  private readonly fetch: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private access?: { token: string; expiresAt: number };

  constructor(private readonly opts: AuthOptions) {
    this.base = opts.base.replace(/\/+$/, "");
    this.fetch = opts.fetch ?? globalThis.fetch;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = opts.now ?? Date.now;
  }

  private file(name: string): string {
    return join(this.opts.dir, name);
  }

  private get login(): string {
    return this.opts.loginCommand ?? "revefi-agent-analyzer login";
  }

  private async readJson<T>(name: string): Promise<T | null> {
    const file = this.file(name);
    try {
      return JSON.parse(await readFile(file, "utf8")) as T;
    } catch (err) {
      if (isMissing(err)) return null;
      throw new SignInError(`${file} is damaged. Delete it and run \`${this.login}\` again.`);
    }
  }

  private notSignedIn(): SignInError {
    return new SignInError(`You're not signed in to ${new URL(this.base).host}. Run \`${this.login}\` first.`, "signed_out");
  }

  /** Runs fn while holding this server's renewal lock, so two processes never renew at once. */
  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const lock = this.file(LOCK);
    for (;;) {
      try {
        const handle = await open(lock, "wx", 0o600);
        await handle.close();
        break;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      }
      let mtime = 0;
      try {
        mtime = (await stat(lock)).mtimeMs;
      } catch (err) {
        if (!isMissing(err)) throw err;
        continue; // Released between the open and the stat; try again at once.
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

  private async saveAccess(token: string, expiresIn: number | undefined): Promise<string> {
    const cached: CachedAccess = { token, expires_at: this.now() + (expiresIn ?? 0) * 1000 };
    this.access = { token, expiresAt: cached.expires_at };
    await writePrivate(this.file(ACCESS), cached);
    return token;
  }

  private async cachedAccess(rejected?: string): Promise<string | null> {
    let cached: CachedAccess | null = null;
    try {
      cached = await this.readJson<CachedAccess>(ACCESS);
    } catch (err) {
      if (!(err instanceof SignInError)) throw err;
      // Only a cache: a damaged one is replaced by renewing.
    }
    if (!cached || cached.token === rejected || cached.expires_at - EXPIRY_MARGIN_MS <= this.now()) return null;
    this.access = { token: cached.token, expiresAt: cached.expires_at };
    return cached.token;
  }

  private async post(url: string, form: Record<string, string>): Promise<{ status: number; body: TokenResponse }> {
    let res: Response;
    try {
      res = await this.fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams(form).toString(),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      throw new SignInError(unreachable(err, new URL(url).host, this.opts.env ?? process.env));
    }
    const text = await res.text();
    try {
      return { status: res.status, body: text ? (JSON.parse(text) as TokenResponse) : {} };
    } catch {
      return { status: res.status, body: {} };
    }
  }

  async config(): Promise<AuthConfig> {
    let res: Response;
    try {
      res = await this.fetch(`${this.base}/api/auth/config`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (err) {
      throw new SignInError(unreachable(err, new URL(this.base).host, this.opts.env ?? process.env));
    }
    if (res.status === 503) throw new SignInError(`${new URL(this.base).host} doesn't offer sign-in yet.`);
    let body: Partial<AuthConfig> | null = null;
    try {
      body = (await res.json()) as Partial<AuthConfig>;
    } catch {
      body = null; // Reported just below as an unexpected configuration.
    }
    if (!res.ok || !body?.domain || !HOST.test(body.domain) || !body.audience || !body.cli_client_id) {
      throw new SignInError(`${new URL(this.base).host} returned an unexpected sign-in configuration. Try again later.`);
    }
    // Tokens go only to the server they were issued for: a server naming another one's API would
    // otherwise collect tokens it could replay there.
    if (!sameOrigin(body.audience, this.base)) {
      throw new SignInError(`${new URL(this.base).host} asked for a sign-in to a different server. Check --api and REVEFI_ANALYZER_API.`);
    }
    return { domain: body.domain, audience: body.audience, cli_client_id: body.cli_client_id };
  }

  /** Starts a device login and remembers it, so `finishLogin` can run in a later process. */
  async startLogin(): Promise<PendingLogin> {
    const config = await this.config();
    const { status, body } = await this.post(`https://${config.domain}/oauth/device/code`, {
      client_id: config.cli_client_id,
      audience: config.audience,
      scope: "openid email offline_access",
    });
    const code = body as TokenResponse & Partial<PendingLogin> & { expires_in?: number; interval?: number };
    if (status !== 200 || !code.device_code || !code.user_code || !code.verification_uri_complete) {
      throw new SignInError(`Couldn't start sign-in (${code.error_description ?? `HTTP ${status}`}). Try again.`);
    }
    // The link is opened in a browser, so it must be an https page on the sign-in domain itself.
    if (!isSignInPage(code.verification_uri_complete, config.domain)) {
      throw new SignInError(`${config.domain} returned an unexpected sign-in link. Try again later.`);
    }
    const pending: PendingLogin = {
      user_code: code.user_code,
      verification_uri_complete: code.verification_uri_complete,
      expires_at: this.now() + (code.expires_in ?? 900) * 1000,
      interval: code.interval ?? 5,
      device_code: code.device_code,
      config,
    };
    await mkdir(this.opts.dir, { recursive: true, mode: 0o700 });
    await writePrivate(this.file(PENDING), pending);
    return pending;
  }

  private async expired(): Promise<SignInError> {
    await rm(this.file(PENDING), { force: true });
    return new SignInError(`The sign-in code expired. Run \`${this.login}\` again.`);
  }

  /** Waits for the user to approve the pending login, then stores the refresh token. */
  async finishLogin(opts: { timeoutMs?: number } = {}): Promise<{ email: string | null }> {
    const pending = await this.readJson<PendingLogin>(PENDING);
    if (!pending) throw new SignInError(`No sign-in is in progress. Run \`${this.login}\` to start one.`);
    const waitUntil = this.now() + (opts.timeoutMs ?? Number.POSITIVE_INFINITY);
    let interval = pending.interval;
    for (;;) {
      if (this.now() >= pending.expires_at) throw await this.expired();
      let body: TokenResponse = {};
      try {
        ({ body } = await this.post(`https://${pending.config.domain}/oauth/token`, {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: pending.device_code,
          client_id: pending.config.cli_client_id,
        }));
      } catch {
        body = {}; // A network blip: keep waiting, more slowly, until the code expires.
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
      // authorization_pending keeps the pace; slow_down, rate limits, outages and garbled replies
      // all slow it.
      if (body.error !== "authorization_pending") interval = Math.min(interval + 5, MAX_POLL_INTERVAL_S);
      const next = this.now() + interval * 1000;
      if (next >= pending.expires_at) throw await this.expired();
      if (next > waitUntil) {
        throw new SignInError(
          `Still waiting for you to approve the sign-in in your browser. Run \`${this.login} --wait\` once you have.`,
          "pending",
        );
      }
      await this.sleep(interval * 1000);
    }
  }

  /** Stores a new sign-in, revoking the one it replaces. */
  private async signedIn(config: AuthConfig, body: TokenResponse): Promise<string | null> {
    const previous = await this.readJson<Credentials>(CREDENTIALS);
    const email = emailFrom(body.id_token);
    await writePrivate(this.file(CREDENTIALS), {
      domain: config.domain,
      audience: config.audience,
      client_id: config.cli_client_id,
      refresh_token: body.refresh_token ?? "",
      email,
    } satisfies Credentials);
    await rm(this.file(PENDING), { force: true });
    await this.saveAccess(body.access_token ?? "", body.expires_in);
    if (previous && previous.refresh_token !== body.refresh_token) await this.revoke(previous);
    return email;
  }

  async email(): Promise<string | null> {
    const creds = await this.readJson<Credentials>(CREDENTIALS);
    if (!creds) throw this.notSignedIn();
    return creds.email;
  }

  /** A valid access token, renewed when needed; `force` means the current one was just rejected. */
  async accessToken(force = false): Promise<string> {
    const rejected = force ? this.access?.token : undefined;
    if (!force && this.access && this.access.expiresAt - EXPIRY_MARGIN_MS > this.now()) return this.access.token;
    const fromDisk = await this.cachedAccess(rejected);
    if (fromDisk) return fromDisk;
    if (!(await this.readJson<Credentials>(CREDENTIALS))) throw this.notSignedIn();
    await mkdir(this.opts.dir, { recursive: true, mode: 0o700 });
    return this.withLock(async () => {
      // Another process may have renewed while this one waited for the lock.
      const renewed = await this.cachedAccess(rejected);
      if (renewed) return renewed;
      const creds = await this.readJson<Credentials>(CREDENTIALS);
      if (!creds) throw this.notSignedIn();
      const { status, body } = await this.post(`https://${creds.domain}/oauth/token`, {
        grant_type: "refresh_token",
        client_id: creds.client_id,
        refresh_token: creds.refresh_token,
      });
      if (body.access_token) {
        // Refresh tokens rotate: the old one stops working once this one is issued.
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

  private async revoke(creds: Credentials): Promise<boolean> {
    try {
      const { status } = await this.post(`https://${creds.domain}/oauth/revoke`, {
        client_id: creds.client_id,
        token: creds.refresh_token,
      });
      return status === 200;
    } catch {
      return false; // The caller reports it; the token still expires on its own.
    }
  }

  /** Forgets the sign-in, revoking its refresh token at Auth0 when it can be reached. */
  async logout(): Promise<{ signedIn: boolean; revoked: boolean }> {
    const creds = await this.readJson<Credentials>(CREDENTIALS);
    await rm(this.file(PENDING), { force: true });
    await rm(this.file(ACCESS), { force: true });
    this.access = undefined;
    if (!creds) return { signedIn: false, revoked: false };
    const revoked = await this.revoke(creds);
    await rm(this.file(CREDENTIALS), { force: true });
    return { signedIn: true, revoked };
  }
}

import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { Auth, breakStaleLock, canonicalHost, SignInError } from "../src/auth.js";
import { fakeFetch, type Handler, json, type Seen } from "./fake-server.js";

const tmp = mkdtempSync(join(tmpdir(), "aa-auth-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const CONFIG = { domain: "auth.test", audience: "https://api.test/api", web_client_id: "web", cli_client_id: "cli" };
const idToken = (email: string) =>
  `h.${Buffer.from(JSON.stringify({ email })).toString("base64url")}.s`;
const DEVICE_CODE = {
  device_code: "dev-1",
  user_code: "ABCD-EFGH",
  verification_uri: "https://auth.test/activate",
  verification_uri_complete: "https://auth.test/activate?user_code=ABCD-EFGH",
  expires_in: 900,
  interval: 5,
};

let n = 0;
function setup(routes: Record<string, Handler[] | Handler>) {
  const dir = join(tmp, `case-${n++}`);
  const { fetch, seen } = fakeFetch({ "GET /api/auth/config": () => json(200, CONFIG), ...routes });
  const sleeps: number[] = [];
  let now = 1_000_000;
  const auth = new Auth({
    base: "https://api.test",
    dir,
    fetch,
    sleep: async (ms) => {
      sleeps.push(ms);
      now += ms;
    },
    now: () => now,
  });
  /** Another CLI process on the same machine and clock, with no network. */
  const otherProcess = () =>
    new Auth({ base: "https://api.test", dir, fetch: (() => Promise.reject(new Error("no network"))) as typeof fetch, now: () => now });
  return { auth, dir, seen, sleeps, otherProcess };
}

const form = (req: Seen | undefined) => Object.fromEntries(new URLSearchParams(String(req?.body)));
const signedIn = (rt = "rt-1", email = "ada@example.com") =>
  json(200, { access_token: "at-1", refresh_token: rt, id_token: idToken(email), expires_in: 3600 });

describe("Auth device login", () => {
  it("asks Auth0 for a code for this API with offline access, and remembers it owner-only", async () => {
    const { auth, dir, seen } = setup({ "POST /oauth/device/code": () => json(200, DEVICE_CODE) });

    const pending = await auth.startLogin();

    expect(pending).toMatchObject({ user_code: "ABCD-EFGH", verification_uri_complete: DEVICE_CODE.verification_uri_complete });
    expect(seen[1]?.url).toBe("https://auth.test/oauth/device/code");
    expect(form(seen[1])).toEqual({ client_id: "cli", audience: "https://api.test/api", scope: "openid email offline_access" });
    expect(statSync(join(dir, "pending-login.json")).mode & 0o077).toBe(0);
  });

  it("polls until approved, slowing down when asked, and keeps the refresh token owner-only", async () => {
    const { auth, dir, seen, sleeps } = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": [
        () => json(403, { error: "authorization_pending" }),
        () => json(429, { error: "slow_down" }),
        () => signedIn(),
      ],
    });
    await auth.startLogin();

    await expect(auth.finishLogin()).resolves.toEqual({ email: "ada@example.com" });

    expect(sleeps).toEqual([5_000, 10_000]);
    expect(form(seen.at(-1))).toEqual({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: "dev-1",
      client_id: "cli",
    });
    const file = join(dir, "credentials.json");
    expect(statSync(file).mode & 0o077).toBe(0);
    expect(JSON.parse(readFileSync(file, "utf8"))).toMatchObject({ refresh_token: "rt-1", email: "ada@example.com" });
    expect(existsSync(join(dir, "pending-login.json"))).toBe(false);
    await expect(auth.accessToken()).resolves.toBe("at-1");
  });

  it("explains a sign-in an Auth0 rule refused, and forgets the code", async () => {
    const { auth, dir } = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": () => json(403, { error: "access_denied", error_description: "unapproved_authentication_method" }),
    });
    await auth.startLogin();

    await expect(auth.finishLogin()).rejects.toThrow(/organization requires its own sign-in/);
    expect(existsSync(join(dir, "pending-login.json"))).toBe(false);
  });

  it.each(["constructor", ""])("falls back to a plain refusal for the description %j", async (desc) => {
    const { auth } = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": () => json(403, { error: "access_denied", error_description: desc }),
    });
    await auth.startLogin();

    await expect(auth.finishLogin()).rejects.toThrow(/^Sign-in was refused or cancelled\. Run/);
  });

  it("says when the code expired", async () => {
    const { auth } = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": () => json(403, { error: "expired_token" }),
    });
    await auth.startLogin();
    await expect(auth.finishLogin()).rejects.toThrow("The sign-in code expired. Run `revefi-agent-analyzer login` again.");
  });

  it("stops waiting at the timeout and keeps the sign-in so --wait can resume it", async () => {
    const { auth, dir } = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": () => json(403, { error: "authorization_pending" }),
    });
    await auth.startLogin();
    await expect(auth.finishLogin({ timeoutMs: 12_000 })).rejects.toThrow(/Run `revefi-agent-analyzer login --wait` once you have/);
    expect(existsSync(join(dir, "pending-login.json"))).toBe(true);
  });

  it("keeps polling, more slowly, through outages, rate limits and network errors", async () => {
    const { auth, sleeps } = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": [
        () => new Response("<html>503</html>", { status: 503, headers: { "content-type": "text/html" } }),
        () => json(429, {}),
        () => Promise.reject(new TypeError("fetch failed")),
        () => signedIn(),
      ],
    });
    await auth.startLogin();
    await expect(auth.finishLogin()).resolves.toEqual({ email: "ada@example.com" });
    expect(sleeps).toEqual([10_000, 15_000, 20_000]);
  });

  it("says the code expired, and forgets it, when it runs out before approval", async () => {
    const { auth, dir } = setup({
      "POST /oauth/device/code": () => json(200, { ...DEVICE_CODE, expires_in: 12 }),
      "POST /oauth/token": () => json(403, { error: "authorization_pending" }),
    });
    await auth.startLogin();
    await expect(auth.finishLogin()).rejects.toThrow("The sign-in code expired. Run `revefi-agent-analyzer login` again.");
    expect(existsSync(join(dir, "pending-login.json"))).toBe(false);
  });

  it("says the server isn't set up for the CLI when no refresh token comes back", async () => {
    const { auth } = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": () => json(200, { access_token: "at", expires_in: 3600 }),
    });
    await auth.startLogin();
    await expect(auth.finishLogin()).rejects.toThrow("api.test isn't set up for command-line sign-in yet.");
  });

  it("names the login command a non-default server needs", async () => {
    const { auth } = setup({});
    const custom = new Auth({ base: "https://api.test", dir: join(tmp, "nowhere"), loginCommand: "revefi-agent-analyzer login --api https://api.test" });
    await expect(custom.email()).rejects.toThrow("Run `revefi-agent-analyzer login --api https://api.test` first.");
    await expect(auth.email()).rejects.toThrow("Run `revefi-agent-analyzer login` first.");
  });

  it.each([
    ["an option for the opener", "-a Calculator"],
    ["another scheme", "file:///etc/passwd"],
    ["another host", "https://evil.test/activate"],
    ["credentials in the link", "https://user:pw@auth.test/activate"],
  ])("never opens a sign-in link that is %s", async (_name, link) => {
    const { auth, dir } = setup({
      "POST /oauth/device/code": () => json(200, { ...DEVICE_CODE, verification_uri_complete: link }),
    });
    await expect(auth.startLogin()).rejects.toThrow("auth.test returned an unexpected sign-in link. Try again later.");
    expect(existsSync(join(dir, "pending-login.json"))).toBe(false);
  });

  it.each(["auth.test/x", "user@auth.test", "auth.test:443", "localhost"])(
    "refuses a sign-in domain that isn't a bare host name: %s",
    async (domain) => {
      const { auth } = setup({ "GET /api/auth/config": () => json(200, { ...CONFIG, domain }) });
      await expect(auth.startLogin()).rejects.toThrow("api.test returned an unexpected sign-in configuration. Try again later.");
    },
  );

  it("never signs in for another server's API, so its tokens can't be replayed there", async () => {
    const { auth, seen } = setup({
      "GET /api/auth/config": () => json(200, { ...CONFIG, audience: "https://analyzer.revefi.com/api" }),
    });
    await expect(auth.startLogin()).rejects.toThrow("api.test asked for a sign-in to a different server.");
    expect(seen).toHaveLength(1);
  });

  it("accepts the analyzer.revefi.com API from optimizer.revefi.com, its new name", async () => {
    const { fetch } = fakeFetch({
      "GET /api/auth/config": () => json(200, { ...CONFIG, audience: "https://analyzer.revefi.com/api" }),
    });
    const auth = new Auth({ base: "https://optimizer.revefi.com", dir: join(tmp, "renamed"), fetch });
    await expect(auth.config()).resolves.toMatchObject({ audience: "https://analyzer.revefi.com/api" });
  });

  it("treats only the renamed prod host as an alias", () => {
    expect(canonicalHost("analyzer.revefi.com")).toBe("optimizer.revefi.com");
    expect(canonicalHost("dev-analyzer.revefi.com")).toBe("dev-analyzer.revefi.com");
    expect(canonicalHost("api.test")).toBe("api.test");
  });

  it("refuses to wait without a started sign-in", async () => {
    const { auth } = setup({});
    await expect(auth.finishLogin()).rejects.toBeInstanceOf(SignInError);
  });

  it("says when the server has no sign-in", async () => {
    const { auth } = setup({ "GET /api/auth/config": () => json(503, { detail: "x" }) });
    await expect(auth.startLogin()).rejects.toThrow("api.test doesn't offer sign-in yet.");
  });
});

describe("Auth tokens", () => {
  /** Signed in; `later` answers the token calls after the first. */
  async function loggedIn(later: Handler[] = [], routes: Record<string, Handler> = {}) {
    const s = setup({
      "POST /oauth/device/code": () => json(200, DEVICE_CODE),
      "POST /oauth/token": [() => signedIn(), ...later],
      ...routes,
    });
    await s.auth.startLogin();
    await s.auth.finishLogin();
    return s;
  }

  it("refreshes on demand and keeps the rotated refresh token", async () => {
    const { auth, dir, seen } = await loggedIn([
      () => json(200, { access_token: "at-2", refresh_token: "rt-2", expires_in: 3600 }),
    ]);

    await expect(auth.accessToken(true)).resolves.toBe("at-2");
    expect(form(seen.at(-1))).toEqual({ grant_type: "refresh_token", client_id: "cli", refresh_token: "rt-1" });
    expect(JSON.parse(readFileSync(join(dir, "credentials.json"), "utf8")).refresh_token).toBe("rt-2");
  });

  it("reuses a cached access token across runs instead of renewing every time", async () => {
    const { seen, otherProcess } = await loggedIn();
    await expect(otherProcess().accessToken()).resolves.toBe("at-1");
    expect(seen.filter((r) => r.url.endsWith("/oauth/token"))).toHaveLength(1);
  });

  it("uses a token another process renewed instead of renewing again", async () => {
    const { auth, seen, otherProcess } = await loggedIn([
      () => json(200, { access_token: "at-2", refresh_token: "rt-2", expires_in: 3600 }),
    ]);
    await auth.accessToken(true); // at-1 was rejected: renews to at-2
    const tokenCalls = seen.filter((r) => r.url.endsWith("/oauth/token")).length;
    await expect(otherProcess().accessToken()).resolves.toBe("at-2");
    expect(seen.filter((r) => r.url.endsWith("/oauth/token"))).toHaveLength(tokenCalls);
  });

  it("keeps the sign-in when renewing is rate limited", async () => {
    const { auth, dir } = await loggedIn([() => json(429, { error: "too_many_requests" })]);
    await expect(auth.accessToken(true)).rejects.toThrow("Sign-in is busy. Wait a minute and try again.");
    expect(existsSync(join(dir, "credentials.json"))).toBe(true);
  });

  it("revokes the sign-in a new login replaces", async () => {
    const { auth, seen } = await loggedIn([() => signedIn("rt-new")], {
      "POST /oauth/revoke": () => new Response(null, { status: 200 }),
    });
    await auth.startLogin();
    await auth.finishLogin();
    expect(form(seen.find((r) => r.url.endsWith("/oauth/revoke")))).toEqual({ client_id: "cli", token: "rt-1" });
  });

  it("forgets an expired sign-in and asks to sign in again", async () => {
    const { auth, dir } = await loggedIn([() => json(403, { error: "invalid_grant" })]);

    await expect(auth.accessToken(true)).rejects.toThrow("Your sign-in to api.test has expired. Run `revefi-agent-analyzer login` again.");
    expect(existsSync(join(dir, "credentials.json"))).toBe(false);
  });

  it("asks to sign in when there is no sign-in", async () => {
    const { auth } = setup({});
    await expect(auth.accessToken()).rejects.toThrow("You're not signed in to api.test. Run `revefi-agent-analyzer login` first.");
  });

  const renewed = () => json(200, { access_token: "at-2", refresh_token: "rt-2", expires_in: 3600 });

  it("waits while another process holds the renewal lock", async () => {
    const { auth, dir, sleeps } = await loggedIn([renewed]);
    const lock = join(dir, "renew.lock");
    writeFileSync(lock, "");
    setTimeout(() => rmSync(lock, { force: true }), 50);

    await expect(auth.accessToken(true)).resolves.toBe("at-2");

    expect(sleeps.filter((ms) => ms === 200).length).toBeGreaterThan(0);
    expect(existsSync(lock)).toBe(false);
  });

  it("breaks a lock left by a process that died mid-renewal", async () => {
    const { auth, dir, sleeps } = await loggedIn([renewed]);
    const lock = join(dir, "renew.lock");
    writeFileSync(lock, "");
    const old = new Date(Date.now() - 10 * 60_000);
    utimesSync(lock, old, old);
    const before = sleeps.length;

    await expect(auth.accessToken(true)).resolves.toBe("at-2");

    expect(sleeps).toHaveLength(before);
    expect(readdirSync(dir).filter((f) => f.includes("lock"))).toEqual([]);
  });

  it("puts back a lock another process took after breaking the same stale one", () => {
    const lock = join(tmp, `taken-${n++}.lock`);
    writeFileSync(lock, "");
    const fresh = statSync(lock).mtimeMs;

    return breakStaleLock(lock, fresh - 10 * 60_000).then(() => {
      expect(statSync(lock).mtimeMs).toBe(fresh);
      expect(readdirSync(tmp).filter((f) => f.startsWith("taken-") && f.endsWith(".stale"))).toEqual([]);
    });
  });

  it("renews instead of failing when the access-token cache is damaged", async () => {
    const { auth, dir } = await loggedIn([renewed]);
    writeFileSync(join(dir, "access-token.json"), "{not json");

    await expect(auth.accessToken(true)).resolves.toBe("at-2");
  });

  it("revokes the refresh token on logout and says so when it couldn't", async () => {
    const revoked = await loggedIn([], { "POST /oauth/revoke": () => new Response(null, { status: 200 }) });
    await expect(revoked.auth.logout()).resolves.toEqual({ signedIn: true, revoked: true });
    expect(form(revoked.seen.at(-1))).toEqual({ client_id: "cli", token: "rt-1" });
    expect(existsSync(join(revoked.dir, "credentials.json"))).toBe(false);

    const unreachable = await loggedIn([], { "POST /oauth/revoke": () => json(503, {}) });
    await expect(unreachable.auth.logout()).resolves.toEqual({ signedIn: true, revoked: false });
    await expect(unreachable.auth.logout()).resolves.toEqual({ signedIn: false, revoked: false });
  });
});

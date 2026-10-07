import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { list } from "tar";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { encodeProjectDir, utcToday } from "../src/collect.js";
import type { Env } from "../src/commands.js";
import { main } from "../src/main.js";
import { fakeFetch, json, type Seen } from "./fake-server.js";

const tmp = mkdtempSync(join(tmpdir(), "cmd-"));
const repo = join(tmp, "repo");
const claude = join(tmp, "claude");
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

beforeEach(() => {
  rmSync(repo, { recursive: true, force: true });
  rmSync(claude, { recursive: true, force: true });
  mkdirSync(repo, { recursive: true });
  const proj = join(claude, "projects", encodeProjectDir(repo));
  mkdirSync(join(proj, "s1", "subagents"), { recursive: true });
  const ts = `${utcToday()}T00:00:01Z`;
  writeFileSync(join(proj, "s1.jsonl"), `${JSON.stringify({ type: "user", cwd: repo, timestamp: ts })}\n`);
  writeFileSync(join(proj, "s1", "subagents", "agent-a.jsonl"), `${JSON.stringify({ type: "assistant" })}\n`);
});

const rec = (id: string, title: string, usd: number, verdict = "optimizable") => ({
  id,
  title,
  verdict,
  description: "",
  cluster: { label: id, occurrences: 2, sessions: 1, window_usd: usd },
  estimated_savings: null,
  fix_prompt: `fix ${id}`,
  fixes: [],
});

function server(finalPhase = "done") {
  return fakeFetch({
    "POST /api/device": () => json(200, { device_id: "d", device_token: "t" }),
    "POST /api/runs": () =>
      json(201, {
        run_id: "r1",
        report_url: "/r/slug",
        upload: { url: "https://bucket.test/u", method: "PUT", headers: { "Content-Type": "application/gzip" }, expires_at: "2999-01-01T00:00:00Z" },
      }),
    "PUT /u": () => new Response(null, { status: 200 }),
    "POST /api/runs/r1/complete": () => json(200, { run_id: "r1", phase: "analyzing", percent: 0, cost_capped: false, report_url: "/r/slug" }),
    "GET /api/runs/r1": [
      () => json(200, { run_id: "r1", phase: "analyzing", percent: 30, cost_capped: false, report_url: "/r/slug" }),
      () => json(200, { run_id: "r1", phase: finalPhase, percent: 100, cost_capped: false, report_url: "/r/slug" }),
    ],
    "GET /api/runs/r1/recommendations": () =>
      json(200, {
        run_id: "r1",
        contract_version: 1,
        generated_at: "x",
        window: {},
        recommendations: [rec("a", "Docs comments resolved by hand", 760), rec("b", "Lean task", 50, "already_lean"), rec("c", "Throwaway Python", 340)],
        root_causes: [],
      }),
    "POST /api/runs/r1/recommendations/a/feedback": () => json(200, {}),
    "POST /api/runs/r1/visibility": () => json(200, { visibility: "link" }),
    "DELETE /api/me/data": () => new Response(null, { status: 204 }),
  });
}

async function run(
  argv: string[],
  opts: { tty?: boolean; answer?: boolean; srv?: ReturnType<typeof server>; env?: NodeJS.ProcessEnv; cwd?: string } = {},
) {
  const srv = opts.srv ?? server();
  const out: string[] = [];
  const err: string[] = [];
  const e: Env = {
    io: { out: (s) => out.push(s), err: (s) => err.push(s) },
    version: "0.1.0",
    cwd: opts.cwd ?? repo,
    env: { CLAUDE_CONFIG_DIR: claude, REVEFI_ANALYZER_API: "https://api.test", ...opts.env },
    isTTY: opts.tty ?? false,
    ask: async () => opts.answer ?? false,
    fetch: srv.fetch,
    sleep: async () => undefined,
    configDir: join(tmp, "config"),
  };
  const code = await main(argv, e);
  return { code, out: out.join("\n"), err: err.join("\n"), seen: srv.seen };
}

const calls = (seen: Seen[]) => seen.map((s) => `${s.method} ${new URL(s.url).pathname}`);

describe("consent", () => {
  it("never uploads without --yes when there is no terminal to ask", async () => {
    const r = await run(["analyze"]);
    expect(r.code).toBe(1);
    expect(r.seen).toEqual([]);
    expect(r.err).toMatch(/^Nothing was uploaded: there is no terminal here to confirm it\. Review .+REDACTION_REPORT\.md, then run `revefi-agent-analyzer upload \.revefi\/upload-preview\/[^`]+` in a terminal\.$/);
    expect(r.err).not.toContain("--yes");
    expect(r.out).toContain("This uploads the redacted transcripts in the preview to api.test for analysis.");
    expect(r.out).toMatch(/^Scope: /);
  });

  it("uploads nothing when the user answers no", async () => {
    const r = await run(["analyze"], { tty: true, answer: false });
    expect(r.code).toBe(1);
    expect(r.seen).toEqual([]);
  });
});

describe("prepare then upload (the plugin's path)", () => {
  it("uploads exactly the previewed files, reports as the plugin, and cleans up the preview", async () => {
    const prep = await run(["prepare", "--json"]);
    expect(prep.code).toBe(0);
    const p = JSON.parse(prep.out) as { preview_dir: string; sessions: number; upload_to: string };
    expect(p).toMatchObject({ sessions: 1, upload_to: "api.test", session_list: [{ id: "s1", day: utcToday() }] });

    const up = await run(["upload", p.preview_dir, "--yes", "--json"], { env: { CLAUDECODE: "1" } });
    expect(up.code).toBe(0);
    expect(calls(up.seen)).toEqual([
      "POST /api/device",
      "POST /api/runs",
      "PUT /u",
      "POST /api/runs/r1/complete",
      "GET /api/runs/r1",
      "GET /api/runs/r1",
      "GET /api/runs/r1/recommendations",
    ]);
    const manifest = JSON.parse(String(up.seen[1]?.body));
    expect(manifest.client).toEqual({ name: "plugin", version: "0.1.0" });

    const tarFile = join(tmp, "sent.tar.gz");
    writeFileSync(tarFile, up.seen[2]?.body as Uint8Array);
    const paths: string[] = [];
    await list({ file: tarFile, onReadEntry: (en) => paths.push(en.path) });
    const proj = encodeProjectDir(repo);
    expect(paths.sort()).toEqual([`projects/${proj}/s1.jsonl`, `projects/${proj}/s1/subagents/agent-a.jsonl`]);

    const result = JSON.parse(up.out) as { run_id: string; report_url: string; phase: string; top: { id: string }[] };
    expect(result).toMatchObject({ run_id: "r1", report_url: "https://api.test/r/slug", phase: "done" });
    expect(result.top.map((t) => t.id)).toEqual(["a", "c"]);
    expect(existsSync(p.preview_dir)).toBe(false);
  });
});

describe("analyze in a terminal", () => {
  it("asks once, uploads, waits and prints the report with the top tasks", async () => {
    const r = await run(["analyze"], { tty: true, answer: true });
    expect(r.code).toBe(0);
    expect(r.err).toContain("Analyzing... 30%");
    expect(r.out).toContain("Report: https://api.test/r/slug");
    expect(r.out).toContain("≈ $1,100 went to 2 repeated tasks in this window (at API pricing).");
    expect(r.out).toMatch(/1\. Docs comments resolved by hand {2}≈ \$760 {2}\(a\)\n {2}2\. Throwaway Python {2}≈ \$340 {2}\(c\)/);
    expect(r.err).toContain("Run r1 started. Report: https://api.test/r/slug");
  });

  it("explains a failed run and exits 1", async () => {
    const r = await run(["analyze", "--yes"], { srv: server("failed") });
    expect(r.code).toBe(1);
    expect(r.err).toContain("The analysis failed on the server.");
  });

  it("exits 3 and says how to keep waiting when the wait times out", async () => {
    const r = await run(["analyze", "--yes", "--timeout", "0"]);
    expect(r.code).toBe(3);
    expect(r.err).toContain("revefi-agent-analyzer status r1 --wait");
  });

  it("explains an empty window without contacting the server", async () => {
    const r = await run(["analyze", "--yes", "--exclude-session", "s1"]);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/^No Claude Code sessions started between/);
    expect(r.seen).toEqual([]);
  });
});

describe("feedback, share and delete", () => {
  it("records an applied fix as coming from the skill", async () => {
    const r = await run(["feedback", "r1", "a", "up", "--applied-pr", "https://github.com/o/r/pull/1"]);
    expect(r.code).toBe(0);
    expect(JSON.parse(String(r.seen[1]?.body))).toEqual({ verdict: "up", source: "skill", applied_pr_url: "https://github.com/o/r/pull/1" });
  });

  it("records a plain rating as the user's", async () => {
    const r = await run(["feedback", "r1", "a", "down"]);
    expect(JSON.parse(String(r.seen[1]?.body))).toEqual({ verdict: "down", source: "user" });
  });

  it("rejects a rating that isn't up or down", async () => {
    expect((await run(["feedback", "r1", "a", "meh"])).code).toBe(2);
  });

  it("shares by link and prints the link", async () => {
    const r = await run(["share", "r1", "link"]);
    expect(r.out).toBe("Anyone with the link can now open the report: https://api.test/r/slug");
  });

  it("has nothing to delete before anything was uploaded", async () => {
    rmSync(join(tmp, "config"), { recursive: true, force: true });
    const r = await run(["delete-my-data", "--yes"]);
    expect(r).toMatchObject({ code: 0, out: "Nothing to delete: nothing has been uploaded from this machine.", seen: [] });
  });

  it("refuses to delete without --yes when there is no terminal, and deletes with it", async () => {
    await run(["status", "r1"]);
    const refused = await run(["delete-my-data"]);
    expect(refused.code).toBe(1);
    expect(refused.seen).toEqual([]);
    const done = await run(["delete-my-data", "--yes"]);
    expect(done.code).toBe(0);
    expect(calls(done.seen)).toEqual(["POST /api/device", "DELETE /api/me/data"]);
  });
});

describe("upload safety", () => {
  const prepared = async () => JSON.parse((await run(["prepare", "--json"])).out) as { preview_dir: string };

  it("never uploads without --yes when there is no terminal, or when --json is used in one", async () => {
    const { preview_dir } = await prepared();
    for (const r of [await run(["upload", preview_dir]), await run(["upload", preview_dir, "--json"], { tty: true, answer: true })]) {
      expect(r.code).toBe(1);
      expect(r.seen).toEqual([]);
      expect(r.err).toMatch(/^Nothing was uploaded/);
    }
  });

  it("explains a preview that no longer exists, in JSON too", async () => {
    const r = await run(["upload", join(repo, ".revefi", "upload-preview", "gone"), "--yes", "--json"]);
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out)).toEqual({ error: { kind: "refused", message: expect.stringMatching(/^No preview at .*run `prepare`/) } });
    expect(r.seen).toEqual([]);
  });

  it("won't send a preview to a different server than the one it was shown for", async () => {
    const { preview_dir } = await prepared();
    const r = await run(["upload", preview_dir, "--yes", "--api", "https://other.test"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("This preview was prepared for api.test, not other.test.");
    expect(r.seen).toEqual([]);
  });

  it("refuses plain http to anything but this machine", async () => {
    const r = await run(["prepare", "--api", "http://analyzer.example"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("The server must use https://");
  });

  it("keeps the run id visible when something fails after the run started", async () => {
    const failing = fakeFetch({
      "POST /api/device": () => json(200, { device_id: "d", device_token: "t" }),
      "POST /api/runs": () => json(201, { run_id: "r1", report_url: "/r/slug", upload: { url: "https://bucket.test/u", headers: {}, expires_at: "2999-01-01T00:00:00Z" } }),
      "PUT /u": () => new Response(null, { status: 200 }),
      "POST /api/runs/r1/complete": () => json(200, { run_id: "r1", phase: "analyzing", percent: 0, cost_capped: false, report_url: "/r/slug" }),
      "GET /api/runs/r1": () => json(500, { detail: "boom" }),
    });
    const r = await run(["analyze", "--yes"], { srv: failing });
    expect(r.code).toBe(1);
    expect(r.err).toContain("Run r1 started. Report: https://api.test/r/slug");
    expect(r.err).toContain("The run was started; check it later with: revefi-agent-analyzer status r1 --wait");
  });

  it("prints one run shape for upload --no-wait and status --json", async () => {
    const { preview_dir } = await prepared();
    const started = await run(["upload", preview_dir, "--yes", "--json", "--no-wait"]);
    const status = await run(["status", "r1", "--json"]);
    const keys = ["cost_capped", "percent", "phase", "report_url", "run_id", "top"];
    expect(Object.keys(JSON.parse(started.out)).sort()).toEqual(keys);
    expect(Object.keys(JSON.parse(status.out)).sort()).toEqual(keys);
  });
});

describe("project scope", () => {
  it("treats the whole git repository as the project when run from a subfolder", async () => {
    execFileSync("git", ["init", "-q", repo]);
    mkdirSync(join(repo, "src", "deep"), { recursive: true });
    // Claude Code records the physical cwd, as git does; on macOS the temp dir is a symlink.
    const real = realpathSync(repo);
    const proj = join(claude, "projects", encodeProjectDir(real));
    mkdirSync(proj, { recursive: true });
    writeFileSync(join(proj, "s9.jsonl"), `${JSON.stringify({ type: "user", cwd: join(real, "src"), timestamp: `${utcToday()}T00:00:02Z` })}\n`);
    const r = await run(["prepare", "--json"], { cwd: join(repo, "src", "deep") });
    expect(r.code).toBe(0);
    const p = JSON.parse(r.out) as { session_list: { id: string }[]; preview_dir: string; scope: string };
    expect(p.session_list.map((x) => x.id)).toContain("s9");
    expect(p.scope).toBe(realpathSync(repo));
    expect(p.preview_dir.startsWith(join(realpathSync(repo), ".revefi", "upload-preview"))).toBe(true);
  });
});

describe("sign-in", () => {
  const AUTH0 = {
    "GET /api/auth/config": () => json(200, { domain: "auth.test", audience: "https://api.test/api", web_client_id: "w", cli_client_id: "cli" }),
    "POST /oauth/device/code": () =>
      json(200, {
        device_code: "dev-1",
        user_code: "ABCD-EFGH",
        verification_uri_complete: "https://auth.test/activate?user_code=ABCD-EFGH",
        expires_in: 900,
        interval: 5,
      }),
    "POST /oauth/token": () =>
      json(200, {
        access_token: "at-1",
        refresh_token: "rt-1",
        id_token: `h.${Buffer.from(JSON.stringify({ email: "ada@example.com" })).toString("base64url")}.s`,
        expires_in: 3600,
      }),
    "POST /oauth/revoke": () => new Response(null, { status: 200 }),
  };
  beforeEach(() => rmSync(join(tmp, "config"), { recursive: true, force: true }));

  it("splits in two for the plugin: the link and code first, then the wait", async () => {
    const start = await run(["login", "--start", "--json"], { srv: fakeFetch(AUTH0) });
    expect(start.code).toBe(0);
    expect(JSON.parse(start.out)).toMatchObject({
      user_code: "ABCD-EFGH",
      verification_uri_complete: "https://auth.test/activate?user_code=ABCD-EFGH",
    });
    expect(start.out).not.toContain("dev-1");

    const done = await run(["login", "--wait", "--json"], { srv: fakeFetch(AUTH0) });
    expect(done.code).toBe(0);
    expect(JSON.parse(done.out)).toEqual({ email: "ada@example.com" });

    const who = await run(["whoami"], { srv: fakeFetch(AUTH0) });
    expect(who.out).toBe("Signed in as ada@example.com.");
  });

  it("opens the browser in a terminal, and prints the link either way", async () => {
    const opened: string[] = [];
    const srv = fakeFetch(AUTH0);
    const out: string[] = [];
    const err: string[] = [];
    const code = await main(["login"], {
      io: { out: (s) => out.push(s), err: (s) => err.push(s) },
      version: "0.1.0",
      cwd: repo,
      env: { REVEFI_ANALYZER_API: "https://api.test" },
      isTTY: true,
      ask: async () => false,
      fetch: srv.fetch,
      sleep: async () => undefined,
      configDir: join(tmp, "config"),
      openUrl: (url) => opened.push(url),
    });
    expect(code).toBe(0);
    expect(opened).toEqual(["https://auth.test/activate?user_code=ABCD-EFGH"]);
    expect(err.join("\n")).toContain("Check that the page shows the code ABCD-EFGH");
    expect(out.join("\n")).toBe("Signed in as ada@example.com.");
  });

  it("reports a missing sign-in as its own error kind for scripts", async () => {
    const r = await run(["whoami", "--json"], { srv: fakeFetch(AUTH0) });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out)).toEqual({
      error: { kind: "sign_in", message: "You're not signed in to api.test. Run `revefi-agent-analyzer login` first." },
    });
  });

  it("signs out, revoking the session", async () => {
    await run(["login", "--start"], { srv: fakeFetch(AUTH0) });
    await run(["login", "--wait"], { srv: fakeFetch(AUTH0) });
    const r = await run(["logout"], { srv: fakeFetch(AUTH0) });
    expect(r.out).toBe("Signed out.");
    expect(calls(r.seen)).toEqual(["POST /oauth/revoke"]);
    expect((await run(["logout"], { srv: fakeFetch(AUTH0) })).out).toBe("You weren't signed in.");
  });
});

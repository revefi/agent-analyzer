import { mkdtempSync, openAsBlob, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ApiError, Client, type RunStatus } from "../src/api.js";
import { SignInError } from "../src/auth.js";
import type { Manifest } from "../src/pack.js";
import { fakeFetch, type Handler, json, type Seen } from "./fake-server.js";

function fakeServer(routes: Parameters<typeof fakeFetch>[0]) {
  const { fetch: fetchImpl, seen } = fakeFetch(routes);
  const sleeps: number[] = [];
  const tokens: boolean[] = [];
  let n = 1;
  const client = new Client({
    base: "https://api.test/",
    // A forced refresh hands out the next token and later calls keep it, as the signed-in Auth does.
    token: async (force) => {
      tokens.push(force);
      if (force) n++;
      return `tok-${n}`;
    },
    userAgent: "revefi-agent-analyzer/test",
    fetch: fetchImpl,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  return { client, seen, sleeps, tokens };
}

const status = (phase: RunStatus["phase"], percent = 50): RunStatus => ({
  run_id: "r1",
  phase,
  percent,
  cost_capped: false,
  report_url: "/r/slug",
});
const manifest: Manifest = {
  format_version: 1,
  tool: "claude-code",
  client: { name: "cli", version: "0.1.0" },
  window: { days: 7, start: "2026-09-25", end: "2026-10-01" },
  session_count: 2,
  bytes: { compressed: 3, uncompressed: 10 },
};

describe("Client run flow", () => {
  it("creates, uploads with the signed headers, completes and polls to done", async () => {
    const upload = { url: "https://bucket.test/u?sig=1", method: "PUT", headers: { "Content-Type": "application/gzip", "If-None-Match": "*", "Content-Length": "3" }, expires_at: "2999-01-01T00:00:00Z" };
    const { client, seen } = fakeServer({
      "POST /api/runs": () => json(201, { run_id: "r1", report_url: "/r/slug", upload }),
      "PUT /u": () => new Response(null, { status: 200 }),
      "POST /api/runs/r1/complete": () => json(200, status("analyzing", 0)),
      "GET /api/runs/r1": [() => json(200, status("analyzing", 40)), () => json(200, status("done", 100))],
    });

    const run = await client.createRun(manifest);
    await client.upload(run.upload, new Blob([new Uint8Array([1, 2, 3])]));
    await client.complete(run.run_id);
    const progress: number[] = [];
    const final = await client.waitForRun("r1", { timeoutMs: 60_000, onProgress: (s) => progress.push(s.percent) });

    expect(final.phase).toBe("done");
    expect(progress).toEqual([40, 100]);
    const create = seen.find((r) => r.url.endsWith("/api/runs"));
    expect(create?.headers.authorization).toBe("Bearer tok-1");
    expect(JSON.parse(String(create?.body))).toEqual(manifest);
    const put = seen.find((r) => r.method === "PUT");
    expect(put?.headers).toEqual(upload.headers);
    expect(put?.headers.authorization).toBeUndefined();
    expect(Array.from(put?.body as Uint8Array)).toEqual([1, 2, 3]);
    expect(client.link(run.report_url)).toBe("https://api.test/r/slug");
  });

  it("returns the last status when the wait times out", async () => {
    const { client } = fakeServer({ "GET /api/runs/r1": () => json(200, status("analyzing")) });
    expect((await client.waitForRun("r1", { timeoutMs: 0 })).phase).toBe("analyzing");
  });
});

describe("Client errors", () => {
  it("renews the sign-in once when the token is rejected", async () => {
    const { client, tokens } = fakeServer({
      "GET /api/runs/r1": [() => json(401, { detail: "Invalid token." }), (r) => json(200, { ...status("done"), token: r.headers.authorization })],
    });
    const s = (await client.status("r1")) as RunStatus & { token: string };
    expect(s.token).toBe("Bearer tok-2");
    expect(tokens).toEqual([false, true]);
  });

  it("asks to sign in again when even a renewed token is rejected", async () => {
    const { client } = fakeServer({ "GET /api/runs/r1": () => json(401, { detail: "Invalid token." }) });
    const err = await client.status("r1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SignInError);
    expect((err as Error).message).toBe("Your sign-in wasn't accepted. Run `revefi-agent-analyzer login` again.");
  });

  it("waits out a rate limit and retries", async () => {
    const { client, sleeps } = fakeServer({
      "GET /api/runs/r1": [() => json(429, { detail: "Too many requests." }, { "retry-after": "3" }), () => json(200, status("done"))],
    });
    expect((await client.status("r1")).phase).toBe("done");
    expect(sleeps).toEqual([3000]);
  });

  it("does not retry the daily quota and shows the server's explanation", async () => {
    const { client, seen } = fakeServer({
      "POST /api/runs": () => json(429, { detail: "You have used today's analysis. Try again tomorrow (UTC)." }),
    });
    await expect(client.createRun(manifest)).rejects.toThrow("You have used today's analysis. Try again tomorrow (UTC).");
    expect(seen.filter((r) => r.url.endsWith("/api/runs"))).toHaveLength(1);
  });

  it("names the flags that shrink an oversized upload", async () => {
    const { client } = fakeServer({
      "POST /api/runs": () => json(413, { detail: "Upload exceeds 209715200 bytes." }),
    });
    await expect(client.createRun(manifest)).rejects.toThrow(/--days.*--exclude-session/);
  });

  it("explains a 409 in terms of the call that hit it", async () => {
    const { client } = fakeServer({
      "POST /api/runs/r1/complete": () => json(409, { detail: "Upload not found. PUT the file first." }),
      "DELETE /api/me/data": () => json(409, { detail: "A run is still in progress. Try again once it finishes." }),
    });
    await expect(client.complete("r1")).rejects.toThrow("The server didn't receive the upload. Run the command again.");
    await expect(client.deleteMyData()).rejects.toThrow("A run is still in progress. Try again once it finishes.");
  });

  it("retries a temporary outage with backoff, then gives up with the status", async () => {
    const { client, sleeps } = fakeServer({
      "GET /api/runs/r1": () => json(503, { detail: "Could not check the upload. Retry this request." }),
    });
    const err = await client.status("r1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(503);
    expect(sleeps).toEqual([2000, 4000]);
  });

  it("turns a network failure into a message naming the host", async () => {
    const client = new Client({
      base: "https://api.test",
      token: async () => "tok-1",
      userAgent: "t",
      fetch: (async () => {
        throw new TypeError("fetch failed");
      }) as typeof fetch,
    });
    await expect(client.status("r1")).rejects.toThrow("Couldn't reach api.test (fetch failed).");
  });

  it("summarises a non-JSON error page instead of dumping it", async () => {
    const { client } = fakeServer({
      "GET /api/runs/r1": () => new Response("<html>bad gateway</html>", { status: 500, headers: { "content-type": "text/html" } }),
    });
    await expect(client.status("r1")).rejects.toThrow("The server returned HTTP 500: <html>bad gateway</html>.");
  });
});

describe("retry policy", () => {
  it("does not retry creating a run on a gateway timeout, but does retry a status read", async () => {
    const a = fakeServer({ "POST /api/runs": () => json(504, { detail: "Gateway Timeout" }) });
    await expect(a.client.createRun(manifest)).rejects.toThrow("HTTP 504");
    expect(a.seen.filter((r) => r.url.endsWith("/api/runs"))).toHaveLength(1);
    const b = fakeServer({ "GET /api/runs/r1": [() => json(504, {}), () => json(200, status("done"))] });
    expect((await b.client.status("r1")).phase).toBe("done");
  });

  it("refreshes the token whichever order outages and a 401 arrive in", async () => {
    const tokenOk = (r: Seen) => (r.headers.authorization === "Bearer tok-2" ? json(200, status("done")) : json(401, {}));
    const routes = (first: Handler[]) => ({ "GET /api/runs/r1": [...first, tokenOk] });
    expect((await fakeServer(routes([() => json(503, {}), () => json(503, {})])).client.status("r1")).phase).toBe("done");
    const afterRefresh = fakeServer(routes([() => json(401, {}), () => json(503, {})]));
    expect((await afterRefresh.client.status("r1")).phase).toBe("done");
    // Only the call straight after the 401 renews; the retry after the 503 reuses that token.
    expect(afterRefresh.tokens).toEqual([false, true, false]);
  });

  it("does not sit out a long Retry-After, and says how long to wait", async () => {
    const { client, sleeps } = fakeServer({
      "GET /api/runs/r1": () => json(429, { detail: "Too many requests." }, { "retry-after": "120" }),
    });
    await expect(client.status("r1")).rejects.toThrow("Too many requests. Wait 120 seconds and try again.");
    expect(sleeps).toEqual([]);
  });

  it("copes with an empty body labelled as JSON", async () => {
    const { client } = fakeServer({
      "GET /api/runs/r1": () => new Response("", { status: 500, headers: { "content-type": "application/json" } }),
    });
    await expect(client.status("r1")).rejects.toThrow("The server returned HTTP 500. Try again in a few minutes.");
  });
});

describe("upload", () => {
  const target = (expires: string, length = "3") => ({
    url: "https://bucket.test/u?X-Amz-Signature=secret-sig",
    method: "PUT",
    headers: { "Content-Type": "application/gzip", "Content-Length": length },
    expires_at: expires,
  });
  const blob = new Blob([new Uint8Array([1, 2, 3])]);

  it("refuses to send an archive whose size no longer matches what was signed", async () => {
    const { client, seen } = fakeServer({});
    await expect(client.upload(target("2999-01-01T00:00:00Z", "4"), blob)).rejects.toThrow("The archive changed after it was packed.");
    expect(seen).toEqual([]);
  });

  it("explains a rejected upload with the storage error code only, never the signed URL or XML", async () => {
    const xml = "<Error><Code>SignatureDoesNotMatch</Code><AWSAccessKeyId>AKIDEXAMPLE</AWSAccessKeyId></Error>";
    const { client } = fakeServer({ "PUT /u": () => new Response(xml, { status: 403 }) });
    const err = (await client.upload(target("2999-01-01T00:00:00Z"), blob).catch((e: unknown) => e)) as Error;
    expect(err.message).toMatch(/^Storage rejected the upload \(HTTP 403, SignatureDoesNotMatch\)\. Update the CLI/);
    expect(err.message).not.toMatch(/AKIDEXAMPLE|secret-sig|bucket\.test/);
    const expired = fakeServer({ "PUT /u": () => new Response("", { status: 403 }) });
    await expect(expired.client.upload(target("2000-01-01T00:00:00Z"), blob)).rejects.toThrow("The upload link expired. Run the command again.");
  });

  it("sends one Content-Length and no chunked encoding over a real socket", async () => {
    const seenHeaders: Record<string, string | string[] | undefined>[] = [];
    const srv = createServer((req, res) => {
      seenHeaders.push(req.headers);
      req.resume();
      req.on("end", () => res.writeHead(200).end());
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    const file = join(mkdtempSync(join(tmpdir(), "up-")), "a.tar.gz");
    writeFileSync(file, Buffer.alloc(1234, 7));
    try {
      const real = new Client({ base: "http://127.0.0.1", token: async () => "tok-1", userAgent: "t" });
      await real.upload(
        { url: `http://127.0.0.1:${port}/u`, method: "PUT", headers: { "Content-Type": "application/gzip", "Content-Length": "1234" }, expires_at: "2999-01-01T00:00:00Z" },
        await openAsBlob(file),
      );
    } finally {
      srv.close();
    }
    expect(seenHeaders[0]?.["content-length"]).toBe("1234");
    expect(seenHeaders[0]?.["transfer-encoding"]).toBeUndefined();
  });
});

describe("error copy", () => {
  it("gives the server's own reason for a missing recommendation and a next step for a long window", async () => {
    const { client } = fakeServer({
      "POST /api/runs/r1/recommendations/x/feedback": () => json(404, { detail: "Recommendation not found." }),
      "POST /api/runs": () => json(422, { detail: "Window is limited to 7 days." }),
    });
    await expect(client.feedback("r1", "x", { verdict: "up", source: "user" })).rejects.toThrow(/^Recommendation not found\.$/);
    await expect(client.createRun(manifest)).rejects.toThrow(/^Window is limited to 7 days\. Use a shorter --days\.$/);
  });

  it("names the underlying network error and hints at proxy settings", async () => {
    const client = new Client({
      base: "https://api.test",
      token: async () => "tok-1",
      userAgent: "t",
      env: { HTTPS_PROXY: "http://proxy:3128" },
      fetch: (async () => {
        throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ENOTFOUND" } });
      }) as typeof fetch,
    });
    await expect(client.status("r1")).rejects.toThrow(
      "Couldn't reach api.test (ENOTFOUND). Check your connection and try again. You have HTTPS_PROXY set; Node uses it only when NODE_USE_ENV_PROXY=1 is also set.",
    );
  });
});

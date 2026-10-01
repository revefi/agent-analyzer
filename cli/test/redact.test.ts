import { describe, expect, it } from "vitest";
import { aliasProjectDir, type Counts, redactJson, redactJsonl, redactLine, scrubText } from "../src/redact.js";

// Fake secrets are assembled at runtime so no secret-shaped literal sits in the repo.
const j = (...parts: string[]) => parts.join("");
const x = (n: number, c = "a") => c.repeat(n);
const FAKE = {
  anthropic: j("sk-", "ant-api03-", x(40, "Z")),
  openai: j("sk-", "proj-", x(48, "Q")),
  github: j("gh", "p_", x(36, "B")),
  githubPat: j("github", "_pat_", x(30, "C")),
  aws: j("AK", "IA", "QWERTYUIOPASDFGH"),
  slack: j("xo", "xb-", "1234567890-", x(12, "d")),
  stripe: j("sk", "_live_", x(24, "e")),
  google: j("AI", "za", x(35, "f")),
  jwt: j("ey", "J", x(20, "g"), ".", x(20, "h"), ".", x(20, "i")),
  pem: j("-----BEGIN ", "RSA PRIVATE KEY-----\n", x(64, "k"), "\n-----END ", "RSA PRIVATE KEY-----"),
};

function scrub(text: string, home?: string): { text: string; counts: Counts } {
  const counts: Counts = {};
  return { text: scrubText(text, counts, home), counts };
}

describe("scrubText", () => {
  it.each([
    ["anthropic-key", FAKE.anthropic, "<ANTHROPIC_KEY>"],
    ["openai-key", FAKE.openai, "<OPENAI_KEY>"],
    ["github-token", FAKE.github, "<GITHUB_TOKEN>"],
    ["github-token", FAKE.githubPat, "<GITHUB_TOKEN>"],
    ["aws-access-key", FAKE.aws, "<AWS_ACCESS_KEY>"],
    ["slack-token", FAKE.slack, "<SLACK_TOKEN>"],
    ["stripe-key", FAKE.stripe, "<STRIPE_KEY>"],
    ["google-api-key", FAKE.google, "<GOOGLE_API_KEY>"],
    ["jwt", FAKE.jwt, "<JWT>"],
    ["private-key", FAKE.pem, "<PRIVATE_KEY>"],
  ])("%s", (id, secret, placeholder) => {
    const r = scrub(`before ${secret} after`);
    expect(r.text).toBe(`before ${placeholder} after`);
    expect(r.counts[id]).toBe(1);
  });

  it("masks bearer tokens, URL credentials and key=value secrets but keeps the key names", () => {
    const r = scrub(
      [
        `curl -H "Authorization: Bearer ${x(32, "t")}"`,
        `postgres://admin:${j("hunter", "2pass")}@db.internal:5432/app`,
        `DB_PASSWORD=${j("sw0rd", "fish")}`,
        `{"api_key": "${j("val", "ue1234")}"}`,
      ].join("\n"),
    );
    expect(r.text).toContain("Bearer <TOKEN>");
    expect(r.text).toContain("postgres://<CREDENTIALS>@db.internal:5432/app");
    expect(r.text).toContain("DB_PASSWORD=<REDACTED>");
    expect(r.text).toContain('"api_key": <REDACTED>');
    expect(r.text).not.toMatch(/hunter2pass|sw0rdfish|value1234/);
  });

  it("masks every value of a .env body, including Read tool line numbers", () => {
    const body = ["     1→# config", "     2→PORT=8080", "     3→export SERVICE_URL=https://x.example", "     4→MODE=prod"].join("\n");
    const counts: Counts = {};
    const r = { text: scrubText(body, counts, undefined, true), counts };
    expect(r.text).toBe(
      ["     1→# config", "     2→PORT=<REDACTED>", "     3→export SERVICE_URL=<REDACTED>", "     4→MODE=<REDACTED>"].join("\n"),
    );
    expect(r.counts["env-file"]).toBe(1);
  });

  it("leaves KEY=value lines alone outside a .env file", () => {
    expect(scrub("BRANCH=main\nCC=clang\nmake build").text).toBe("BRANCH=main\nCC=clang\nmake build");
  });

  it("leaves prose that merely contains an assignment alone", () => {
    expect(scrub("Set MODE=prod before you deploy, then run the tests.").text).toBe(
      "Set MODE=prod before you deploy, then run the tests.",
    );
  });

  it("replaces long base64 blobs", () => {
    expect(scrub(x(1200, "A")).text).toBe("<base64 omitted>");
  });

  it("rewrites the home directory to ~ only at a path boundary", () => {
    const r = scrub("/Users/pat/repo and /Users/patrick/other", "/Users/pat");
    expect(r.text).toBe("~/repo and /Users/patrick/other");
    expect(r.counts["home-path"]).toBe(1);
  });

  it("rewrites the folder-name form of the home path the same way as the folder alias", () => {
    const r = scrub("Read ~/.claude/projects/-Users-pat-repo/memory/a.md and -Users-patrick-x", "/Users/pat");
    expect(r.text).toBe("Read ~/.claude/projects/~-repo/memory/a.md and -Users-patrick-x");
    expect(aliasProjectDir("-Users-pat-repo", "/Users/pat")).toBe("~-repo");
    expect(aliasProjectDir("-Users-patrick-x", "/Users/pat")).toBe("-Users-patrick-x");
    expect(aliasProjectDir("-Users-pat", "/Users/pat")).toBe("~");
    expect(aliasProjectDir("-srv-app", undefined)).toBe("-srv-app");
  });

  it("does not touch ordinary text or token counters", () => {
    const text = 'usage: {"input_tokens": 1200, "output_tokens": 300} — see README.md';
    expect(scrub(text)).toEqual({ text, counts: {} });
  });
});

describe("scrubText: more secret shapes", () => {
  it.each([
    ["databricks-token", j("dapi", x(32, "e"))],
    ["npm-token", j("npm_", x(36, "N"))],
    ["gitlab-token", j("glpat-", x(20, "g"))],
    ["huggingface-token", j("hf_", x(34, "H"))],
    ["sendgrid-key", j("SG.", x(22, "s"), ".", x(43, "t"))],
    ["google-oauth", j("ya29.", x(40, "y"))],
  ])("%s", (id, secret) => {
    const r = scrub(`token in output: ${secret}`);
    expect(r.text).not.toContain(secret);
    expect(r.counts[id]).toBe(1);
  });

  it("masks passwords given on the command line and in headers", () => {
    const pw = j("hunter", "2pass");
    const r = scrub(
      [
        `psql --password ${pw} -h db`,
        `mysql -u root -p${pw} app`,
        `curl -u admin:${pw} https://x.example`,
        `curl -H "Authorization: Basic ${x(24, "Q")}"`,
        `Cookie: session=${x(30, "c")}; theme=dark`,
        `aws configure set aws_secret_access_key ${x(40, "W")}`,
      ].join("\n"),
    );
    expect(r.text).not.toContain(pw);
    expect(r.text).not.toMatch(/QQQQ|cccc|WWWW/);
    expect(r.text).toContain("psql --password <REDACTED> -h db");
    expect(r.text).toContain("Authorization: Basic <TOKEN>");
  });

  it("redacts all of a password that contains spaces, @ or an empty user", () => {
    const r = scrub(
      [`password = "correct horse battery staple"`, `postgres://u:${j("p@", "ss")}@db/app`, `redis://:${j("pw", "1234")}@cache:6379`].join("\n"),
    );
    expect(r.text).toBe(["password = <REDACTED>", "postgres://<CREDENTIALS>@db/app", "redis://<CREDENTIALS>@cache:6379"].join("\n"));
  });

  it("redacts a private key whose END line was cut off", () => {
    const cut = j("-----BEGIN ", "OPENSSH PRIVATE KEY-----\n", x(64, "k"), "\n", x(64, "k"));
    expect(scrub(`$ head -3 id_ed25519\n${cut}`).text).toBe("$ head -3 id_ed25519\n<PRIVATE_KEY>");
  });

  it("strips base64 data URIs and long base64url runs embedded in text", () => {
    const r = scrub(`<img src="data:image/png;base64,${x(200, "A")}"> and ${x(2500, "_")}`);
    expect(r.text).toBe('<img src="data:image/png;base64,<base64 omitted>"> and <base64 omitted>');
  });

  it("leaves code that only names secrets intact", () => {
    const code = [
      "function login(password: string, token?: string) {}",
      "const token = getToken(req);",
      "export DB_PASSWORD=${DB_PASSWORD}",
      "const key = process.env.API_KEY;",
      "if (secret === null) return;",
    ].join("\n");
    expect(scrub(code)).toEqual({ text: code, counts: {} });
  });

  it("is idempotent and does not count its own placeholders", () => {
    const once = scrub(`ANTHROPIC_API_KEY=${FAKE.anthropic} and ${FAKE.github}`);
    expect(once.counts).toEqual({ "anthropic-key": 1, "github-token": 1 });
    expect(scrub(once.text)).toEqual({ text: once.text, counts: {} });
  });

  it("rewrites the home path at every path boundary, and never a bare /", () => {
    const r = scrub("cd /Users/pat; ls (/Users/pat) `/Users/pat`, /Users/pat. /Users/pat-old", "/Users/pat/");
    expect(r.text).toBe("cd ~; ls (~) `~`, ~. /Users/pat-old");
    expect(scrub("a // b", "/").text).toBe("a // b");
  });

  it.each([
    ["a", "a".repeat(1_000_000)],
    ["a.", "a.".repeat(500_000)],
    ["spaces then 1x", `${" ".repeat(1_000_000)}1x`],
    ["hex", "0123456789abcdef".repeat(62_500)],
    ["dashes", "-".repeat(1_000_000)],
    ["token=", "token=".repeat(160_000)],
    ["scheme://", `${"http://a:".repeat(100_000)}`],
    ["mysql", `mysql ${"x ".repeat(500_000)}`],
  ])("stays fast on a megabyte of %s", (label, input) => {
    const t0 = performance.now();
    scrubText(input, {}, "/Users/pat", true);
    expect(performance.now() - t0, label).toBeLessThan(1500);
  });
});

describe("redactLine", () => {
  it("redacts values stored under secret-named JSON keys, not token counters", () => {
    const line = JSON.stringify({
      message: {
        content: [{ type: "tool_use", input: { password: j("Hunter2", "Hunter2"), env: { AWS_SECRET_ACCESS_KEY: x(40, "W") } } }],
        usage: { input_tokens: 1200, output_tokens: 300 },
      },
    });
    const counts: Counts = {};
    const parsed = JSON.parse(redactLine(line, counts) ?? "");
    expect(parsed.message.content[0].input).toEqual({ password: "<REDACTED>", env: { AWS_SECRET_ACCESS_KEY: "<REDACTED>" } });
    expect(parsed.message.usage).toEqual({ input_tokens: 1200, output_tokens: 300 });
    expect(counts["secret-key"]).toBe(2);
  });

  it("redacts double-encoded JSON in a tool result", () => {
    const text = JSON.stringify(JSON.stringify({ password: j("abcd", "1234") }));
    expect(scrub(text).text).not.toContain("abcd1234");
  });

  it("masks .env values when Claude read or wrote a .env file", () => {
    const read = JSON.stringify({
      message: { content: [{ type: "tool_result", content: "     1→PORT=8080\n     2→MODE=prod" }] },
      toolUseResult: { type: "text", file: { filePath: "/repo/.env.local", content: "PORT=8080\nMODE=prod" } },
    });
    const write = JSON.stringify({ message: { content: [{ type: "tool_use", input: { file_path: "/repo/.env", content: "MODE=prod" } }] } });
    const counts: Counts = {};
    const out = `${redactLine(read, counts)}${redactLine(write, counts)}`;
    expect(out).not.toMatch(/8080|=prod/);
    expect(out).toContain("PORT=<REDACTED>");
  });

  it("scrubs a secret nested inside a JSON-encoded tool result and keeps valid JSON", () => {
    const inner = JSON.stringify({ config: { token: j("abcd", "efgh1234") } });
    const line = JSON.stringify({
      type: "user",
      message: { content: [{ type: "tool_result", content: `cat config.json\n${inner}` }] },
    });
    const counts: Counts = {};
    const out = redactLine(line, counts);
    expect(out).toBeDefined();
    const parsed = JSON.parse(out ?? "");
    expect(JSON.stringify(parsed)).not.toContain("efgh1234");
    expect(counts["secret-assignment"]).toBe(1);
  });

  it("strips image data and whole-file copies but keeps the record's shape", () => {
    const line = JSON.stringify({
      message: { content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0K" } }] },
      toolUseResult: { filePath: "/tmp/a.ts", originalFile: "const a = 1;\n", structuredPatch: [] },
    });
    const counts: Counts = {};
    const parsed = JSON.parse(redactLine(line, counts) ?? "");
    expect(parsed.message.content[0].source).toEqual({ type: "base64", media_type: "image/png", data: "<image omitted>" });
    expect(parsed.toolUseResult.originalFile).toBe("<file omitted>");
    expect(parsed.toolUseResult.filePath).toBe("/tmp/a.ts");
    expect(counts).toEqual({ image: 1, "original-file": 1 });
  });

  it("drops a torn line instead of uploading it unscrubbed", () => {
    const counts: Counts = {};
    expect(redactLine(`{"type":"assistant","text":"${FAKE.aws}`, counts)).toBeUndefined();
    expect(counts["unparsable-line"]).toBe(1);
  });
});

describe("redactJsonl / redactJson", () => {
  it("returns one valid JSON object per line", () => {
    const text = `${JSON.stringify({ a: FAKE.github })}\n\n${JSON.stringify({ b: 1 })}\n{"torn`;
    const out = redactJsonl(text, {});
    const lines = out.trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    for (const l of lines) expect(() => JSON.parse(l)).not.toThrow();
    expect(out).not.toContain(FAKE.github);
  });

  it("redacts a meta.json document", () => {
    expect(redactJson(JSON.stringify({ description: `use ${FAKE.openai}` }), {})).toBe(
      JSON.stringify({ description: "use <OPENAI_KEY>" }),
    );
  });
});

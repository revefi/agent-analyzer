import { describe, expect, it } from "vitest";
import { validateLuhn, validateVerhoeff } from "../src/pii.js";
import { aliasProjectDir, type Counts, errorMessage, redactJson, redactJsonl, redactLine, scrubText } from "../src/redact.js";

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

  it("replaces the username wherever it stands alone, unless it is generic or short", () => {
    const r = scrub("cd /private/var/tmp/_bazel_patricia/b1 && ls Users/patricia/repo patricias", "/Users/patricia");
    expect(r.text).toBe("cd /private/var/tmp/_bazel_{USER}/b1 && ls Users/{USER}/repo patricias");
    expect(r.counts.username).toBe(2);
    expect(scrub("sudo -u ubuntu ls /tmp/ubuntu", "/home/ubuntu").text).toBe("sudo -u ubuntu ls /tmp/ubuntu");
    expect(scrub("the pat file", "/Users/pat").text).toBe("the pat file");
    expect(scrub("image jenkins/jenkins:lts", "/home/jenkins").text).toBe("image jenkins/jenkins:lts");
  });

  it("names a project folder with the username the same way in paths and folder names", () => {
    const home = "/Users/patricia";
    const folder = aliasProjectDir("-Users-patricia-patricia-site", home);
    expect(folder).toBe("~-{USER}-site");
    expect(scrub("Read ~/.claude/projects/-Users-patricia-patricia-site/memory/a.md", home).text).toBe(
      `Read ~/.claude/projects/${folder}/memory/a.md`,
    );
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
    ["dotted numbers", "1.".repeat(500_000)],
    ["spaced digits", "1 ".repeat(500_000)],
    ["hex and colons", "a1:".repeat(330_000)],
    ["local parts and @", "a.b@".repeat(250_000)],
    ["domain labels", `a@${"b1.".repeat(330_000)}`],
    ["IBAN groups", `GB82 ${"AB12 ".repeat(200_000)}`],
    ["phone groups", `+1 ${"12 ".repeat(330_000)}`],
    ["dashed and quoted words", "a-b'".repeat(250_000)],
    ["UPI local parts", "a.b@".repeat(250_000)],
    ["Indian numbers", "91 98765 ".repeat(110_000)],
    ["Aadhaar groups", "2345 ".repeat(200_000)],
    ["plus and digit runs", `+${"1".repeat(30)}x `.repeat(30_000)],
    ["labels and digits", "mobile_no=987654321 ".repeat(50_000)],
  ])("stays fast on a megabyte of %s", (label, input) => {
    const t0 = performance.now();
    scrubText(input, {}, "/Users/pat", true);
    expect(performance.now() - t0, label).toBeLessThan(1500);
  });
});

describe("scrubText: personal data", () => {
  it.each([
    [
      "email",
      "send the test log to jane.doe@corp.io",
      "send the test log to <EMAIL>",
    ],
    [
      "email",
      "replace the placeholder with jane.doe@corp.io",
      "replace the placeholder with <EMAIL>",
    ],
    [
      "email",
      "# userEmail\nThe address is jane@corp.io. Use it",
      "# userEmail\nThe address is <EMAIL>. Use it",
    ],
    ["email", "old: jane@corp.io_old", "old: <EMAIL>_old"],
    ["phone", "call +1 (415) 555-0132.", "call <PHONE>."],
    [
      "phone",
      "call 415-555-0132, (415) 555-0199 or 415 555 0100",
      "call <PHONE>, <PHONE> or <PHONE>",
    ],
    ["phone", "call 1-415-555-0132", "call <PHONE>"],
    [
      "phone",
      "UK +44 20 7946 0958, FR +33 1 23 45 67 89",
      "UK <PHONE>, FR <PHONE>",
    ],
    [
      "card-number",
      "card 4111 1111 1111 1111 on file",
      "card <CARD_NUMBER> on file",
    ],
    ["card-number", "card 4111-1111-1111-1111", "card <CARD_NUMBER>"],
    ["iban", "IBAN GB82WEST12345698765432 to pay", "IBAN <IBAN> to pay"],
    ["iban", "IBAN GB82 WEST 1234 5698 7654 32 IS MINE", "IBAN <IBAN> IS MINE"],
    ["iban", "ES91 2100 0418 4502 0005 1332 TO PAY", "<IBAN> TO PAY"],
    ["iban", "BE68 5390 0754 7034 FROM me, gb82west12345698765432", "<IBAN> FROM me, <IBAN>"],
    ["card-number", "card 4111 1111 1111 1111 12/27 cvv 123, 4111111111111111 123", "card <CARD_NUMBER> 12/27 cvv 123, <CARD_NUMBER> 123"],
    ["card-number", "amex 3782 822463 10005 or 4111.1111.1111.1111", "amex <CARD_NUMBER> or <CARD_NUMBER>"],
    ["ssn", "SSN 123 45 6789", "SSN <SSN>"],
    ["phone", "DE +49 89 12345678 and +49 30 901820", "DE <PHONE> and <PHONE>"],
    ["email", "?u=jane%40corp.io and _jane@corp.io", "?u=<EMAIL> and <EMAIL>"],
    ["ssn", "the number is 123-45-6789", "the number is <SSN>"],
    [
      "national-id",
      "NI AB 12 34 56 C, SIN 046-454-286",
      "NI <NATIONAL_ID>, SIN <NATIONAL_ID>",
    ],
    ["iban", "IBAN BE68 5390 0754 7034 from your main bank", "IBAN <IBAN> from your main bank"],
    ["email", "mail o'brien@corp.io, jöran@corp.de or -jane@corp.io", "mail <EMAIL>, <EMAIL> or -<EMAIL>"],
    [
      "ip-address",
      "client 52.14.200.1 connected",
      "client <IP_ADDRESS> connected",
    ],
    [
      "ip-address",
      "from 2001:db8:85a3::8a2e:370:7334 and 2600:9000:24d9:4800:7:29a6:f140:93a1",
      "from <IP_ADDRESS> and <IP_ADDRESS>",
    ],
    ["phone", "call +91-9876543210, 98765 43210 or 0 98765 43210", "call <PHONE>, <PHONE> or <PHONE>"],
    ["phone", "phone: 9876543210, {\"mobile_number\": \"09876543210\"}, whatsappNo=919876543210", "phone: <PHONE>, {\"mobile_number\": \"<PHONE>\"}, whatsappNo=<PHONE>"],
    ["phone", "UK +44-2079460958, IN +919876543210", "UK <PHONE>, IN <PHONE>"],
    ["phone", "call 9876-543-210, 98 7654 3210 or 91-98765-43210", "call <PHONE>, <PHONE> or <PHONE>"],
    ["upi-id", "pay ravi@yescred, ravi@fifederal or 9876543210@anybank", "pay <UPI_ID>, <UPI_ID> or <UPI_ID>"],
    ["national-id", "Aadhaar no: 234567890124, 2345.6789-0124", "Aadhaar no: <NATIONAL_ID>, <NATIONAL_ID>"],
    ["national-id", "{\"aadhaar_number\": \"234567890124\"} aadhaarNo=234567890124", "{\"aadhaar_number\": \"<NATIONAL_ID>\"} aadhaarNo=<NATIONAL_ID>"],
    ["upi-id", "pay ravi@jio or ravi@hsbc", "pay <UPI_ID> or <UPI_ID>"],
    ["phone", "userPhone: 9876543210, PHONE_NO=9876543210, Phone number: 9876543210", "userPhone: <PHONE>, PHONE_NO=<PHONE>, Phone number: <PHONE>"],
    ["upi-id", "pay ravi.kumar@okhdfcbank or ravi@ybl", "pay <UPI_ID> or <UPI_ID>"],
    ["national-id", "IDs 2345 6789 0124 or 2345-6789-0124", "IDs <NATIONAL_ID> or <NATIONAL_ID>"],
    ["national-id", "PAN ABCPE1234F", "PAN <NATIONAL_ID>"],
    ["card-number", "RuPay 8171 2345 6789 0125", "RuPay <CARD_NUMBER>"],
  ])("%s: %s", (id, input, output) => {
    const r = scrub(input);
    expect(r.text).toBe(output);
    expect(r.counts[id]).toBeGreaterThan(0);
  });

  it("leaves code, versions, IDs and infrastructure addresses alone", () => {
    const text = [
      "pnpm add typescript@7.0.2 vitest@5.0.3",
      "git clone git@github.com:org/repo.git",
      "id 60701899-2693-4533-a1b2-c3d4e5f6a7b8, sha 98025da, uuid be72-e9da7b9c9972",
      "max 2147483648, ts 1728475200000, date 2026-10-09, at 12:30:45, took 12.5-13.5s",
      "@@ -12,7 +12,8 @@ const userName = getUser(req); let x: f64::consts::PI; u8::MAX",
      "- [4.3.2.1. Property](#p) in v1.2.3.4, then 4.3.12.10.2.",
      "hosts 10.0.4.12, 172.31.0.5, 192.168.1.1, 127.0.0.1, ::1, fe80::1ff:fe23:4567:890a",
      "a[1::2], s[2::], B2::C, dead:beef::1, git@ssh.dev.azure.com:v3/org/repo",
      "npm i @paytm/sdk @ybl/ui, epoch 1696871234, offset +1 2 34, AWSKEYNAME1",
      "mem 8589934592 bytes, limit: 6442450944, arn:aws:iam::234567890124:role/x, at 202610121230",
      "+86400000, +2026-10-12, Abcpe1234F, abcpe1234f, react1234s build2024a",
      "ports 60000-65535, rows_produced: 7234567891, bytes_scanned 6234567891, uid 234567890124",
      "arn:aws:iam::916789012345:role/x, 9876543210 rows",
      "total_calls: 7234567891, hotel_id=8123456789, cancelled_rows: 9876543210, telemetry_bytes 9123456789",
      "contact_count: 7123456789, GUID=234567890124, UUID 234567890124",
    ].join("\n");
    expect(scrub(text)).toEqual({ text, counts: {} });
  });

  it("leaves numbers that fail the checksum", () => {
    const text =
      "order 4111 1111 1111 1112, IBAN GB00WEST12345698765432, SSN 000-12-3456, Aadhaar 2345 6789 0123";
    expect(scrub(text)).toEqual({ text, counts: {} });
  });

  it("removes randomly generated valid values from code-like text", () => {
    let seed = 7;
    const rand = (n: number) => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return (seed >>> 16) % n;
    };
    const digits = (n: number) => Array.from({ length: n }, () => rand(10)).join("");
    const withCheck = (base: string, ok: (v: string) => boolean) =>
      [..."0123456789"].map((d) => base + d).find(ok) ?? "";
    const iban = () => {
      const bban = `WEST${digits(14)}`;
      const n = [...`${bban}GB00`].map((c) => (/[A-Z]/.test(c) ? c.charCodeAt(0) - 55 : c)).join("");
      return `GB${String(98n - (BigInt(n) % 97n)).padStart(2, "0")}${bban}`;
    };
    const makers = [
      () => withCheck(`4${digits(14)}`, (v) => validateLuhn(v)),
      () => withCheck(`${2 + rand(8)}${digits(10)}`, validateVerhoeff).replace(/(\d{4})(?=\d)/g, "$1 "),
      iban,
      () => `user${digits(3)}@corp${digits(2)}.io`,
      () => `+91 ${6 + rand(4)}${digits(4)} ${digits(5)}`,
      () => `name.${digits(2)}@oksbi`,
    ];
    const templates = [
      (v: string) => `const user = { id: 42, contact: "${v}", plan: "pro" };`,
      (v: string) => `INSERT INTO payments VALUES ('${v}', 1999);`,
      (v: string) => `$ curl -d 'value=${v}&exp=12/27' https://api.corp.io/pay`,
      (v: string) => `2026-10-09T12:00:00Z INFO user=${v} action=login`,
      (v: string) => `| ${v} | active |`,
    ];
    for (let i = 0; i < 600; i++) {
      const value = makers[i % makers.length]!();
      const text = templates[rand(templates.length)]!(value);
      expect(scrub(text).text, text).not.toContain(value);
    }
  });

  it("redacts every match in a long tool output", () => {
    const text = [...Array(20_000).keys()]
      .map((i) => `user${i}@corp.io 52.14.200.${i % 250}`)
      .join("\n");
    const r = scrub(text);
    expect(r.counts.email).toBe(20_000);
    expect(r.counts["ip-address"]).toBe(20_000);
    expect(r.text).not.toMatch(/@corp\.io|52\.14/);
  });
});

describe("redactLine", () => {
  it("redacts personal data inside JSON quoted in a message and keeps valid JSON", () => {
    const inner = JSON.stringify({ user: { email: "jane@corp.io", phone: "+91 98765 43210" } });
    const line = JSON.stringify({ message: { content: [{ type: "text", text: `user.json has\n${inner}` }] } });
    const counts: Counts = {};
    const out = redactLine(line, counts) ?? "";
    expect(() => JSON.parse(out)).not.toThrow();
    expect(out).not.toMatch(/jane@corp|98765/);
    expect(counts).toMatchObject({ email: 1, phone: 1 });
  });

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

  it("redacts a secret-named value that only looks like a placeholder, but keeps real placeholders", () => {
    const counts: Counts = {};
    const line = JSON.stringify({ input: { password: j("<hunter", "2>"), token: "<REDACTED>" } });
    expect(JSON.parse(redactLine(line, counts) ?? "").input).toEqual({ password: "<REDACTED>", token: "<REDACTED>" });
    expect(counts["secret-key"]).toBe(1);
  });

  it("redacts every value in arrays and objects under a secret-named key", () => {
    const line = JSON.stringify({
      input: { token: [j("abc", "123"), 42], credentials: { user: "dev", pass: j("hun", "ter2"), enabled: true } },
    });
    expect(JSON.parse(redactLine(line, {}) ?? "").input).toEqual({
      token: ["<REDACTED>", "<REDACTED>"],
      credentials: { user: "<REDACTED>", pass: "<REDACTED>", enabled: true },
    });
  });

  it("redacts a bare secret before `;`, but not a call or member access", () => {
    const redacted = [
      j("export DB_PASSWORD=hunter", "2pass;"),
      j("password = s3cret", "Value;"),
      j("api_key: abcd", "1234;"),
    ];
    for (const line of redacted) expect(scrubText(line, {})).toContain("<REDACTED>");
    const code = ["const token = getToken();", "token = req.headers.authorization;", "secret = config.secret;"];
    for (const line of code) expect(scrubText(line, {})).toBe(line);
  });

  it("redacts double-encoded JSON in a tool result", () => {
    const text = JSON.stringify(JSON.stringify({ password: j("abcd", "1234") }));
    expect(scrub(text).text).not.toContain("abcd1234");
  });

  it("masks .env values when Claude wrote a .env file", () => {
    const write = JSON.stringify({
      message: { content: [{ type: "tool_use", input: { file_path: "/repo/.env", content: "PORT=8080\nMODE=prod" } }] },
    });
    const out = redactLine(write, {}) ?? "";
    expect(out).not.toMatch(/8080|=prod/);
    expect(out).toContain("PORT=<REDACTED>");
  });

  it("scrubs a secret nested inside JSON quoted in a message and keeps valid JSON", () => {
    const inner = JSON.stringify({ config: { token: j("abcd", "efgh1234") } });
    const line = JSON.stringify({
      type: "assistant",
      message: { content: [{ type: "text", text: `config.json has\n${inner}` }] },
    });
    const counts: Counts = {};
    const out = redactLine(line, counts);
    expect(out).toBeDefined();
    const parsed = JSON.parse(out ?? "");
    expect(JSON.stringify(parsed)).not.toContain("efgh1234");
    expect(counts["secret-assignment"]).toBe(1);
  });

  it("strips image data but keeps the record's shape", () => {
    const line = JSON.stringify({
      message: { content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0K" } }] },
    });
    const counts: Counts = {};
    const parsed = JSON.parse(redactLine(line, counts) ?? "");
    expect(parsed.message.content[0].source).toEqual({ type: "base64", media_type: "image/png", data: "<image omitted>" });
    expect(counts).toEqual({ image: 1 });
  });

  it("drops a successful tool's output and its structured duplicate; a failure keeps its message", () => {
    const line = JSON.stringify({
      type: "user",
      message: {
        content: [
          { type: "tool_result", tool_use_id: "t1", content: "const a = 1;\n" },
          { type: "tool_result", tool_use_id: "t2", is_error: true, content: [{ type: "text", text: "Error: boom" }] },
        ],
      },
      toolUseResult: { filePath: "/tmp/a.ts", originalFile: "const a = 1;\n", structuredPatch: [] },
    });
    const counts: Counts = {};
    const parsed = JSON.parse(redactLine(line, counts) ?? "");
    expect(parsed).not.toHaveProperty("toolUseResult");
    expect(parsed.message.content).toEqual([
      { type: "tool_result", tool_use_id: "t1", content: "" },
      { type: "tool_result", tool_use_id: "t2", is_error: true, content: "Error: boom" },
    ]);
    expect(counts).toEqual({});
  });

  it("sends only the error lines of a long failed output, redacted", () => {
    const output = [
      "Exit code 1",
      ...Array.from({ length: 400 }, (_, i) => `PASS tests/case_${i}.py`),
      "Traceback (most recent call last):",
      '  File "app.py", line 3, in <module>',
      `ValueError: bad token ${j("ghp_", x(36, "A"))}`,
      "FAILED tests/test_app.py::test_load - ValueError",
      "1 failed, 400 passed in 3.2s",
    ].join("\n");
    const line = JSON.stringify({ message: { content: [{ type: "tool_result", tool_use_id: "t1", is_error: true, content: output }] } });
    const counts: Counts = {};
    const sent = JSON.parse(redactLine(line, counts) ?? "").message.content[0].content as string;
    expect(sent.split("\n")).toEqual([
      "Exit code 1",
      "Traceback (most recent call last):",
      "ValueError: bad token <GITHUB_TOKEN>",
      "FAILED tests/test_app.py::test_load - ValueError",
      "1 failed, 400 passed in 3.2s",
    ]);
    expect(counts["github-token"]).toBe(1);
  });

  it("redacts a secret that straddles the line and message cuts", () => {
    const token = j("ghp_", x(36, "Q"));
    const ansiToken = `\x1b[31m${token}\x1b[0m`;
    const output = [
      "Exit code 1",
      `Error: ${"a".repeat(185)} ${token} tail`,
      `Error: ${"b".repeat(150)}`,
      `Error: ${"c".repeat(150)} ${ansiToken}`,
      `FAILED ${"d".repeat(150)}`,
      `done ${token}`,
    ].join("\n");
    const line = JSON.stringify({ message: { content: [{ type: "tool_result", tool_use_id: "t1", is_error: true, content: output }] } });
    const sent = JSON.parse(redactLine(line, {}) ?? "").message.content[0].content as string;
    expect(sent).not.toContain("ghp_Q");
    expect(sent).not.toMatch(/Q{8}/);
  });

  it("caps an error message at 6 lines and 500 characters", () => {
    const long = Array.from({ length: 20 }, (_, i) => `Error: ${"x".repeat(300)} ${i}`).join("\n");
    const msg = errorMessage(long);
    expect(msg.split("\n").length).toBeLessThanOrEqual(6);
    expect(msg.length).toBeLessThanOrEqual(501);
    expect(errorMessage("\n\n")).toBe("");
  });

  it("keeps the interruption marker of an interrupted tool call", () => {
    const line = JSON.stringify({
      message: { content: [{ type: "tool_result", tool_use_id: "t1", content: "[Request interrupted by user for tool use]" }] },
    });
    const parsed = JSON.parse(redactLine(line, {}) ?? "");
    expect(parsed.message.content[0].content).toBe("[Request interrupted");
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

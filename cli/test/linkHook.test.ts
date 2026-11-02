import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalHost } from "../src/auth.js";
import { hookCommand, type HookInput, type LinkContext, linkMessage } from "../src/linkHook.js";
import { main, USAGE } from "../src/main.js";

const REPORT = "https://optimizer.revefi.com/r/abc";
const SIGN_IN = "https://auth.revefi.com/activate?user_code=ABCD-EFGH";
const ctx: LinkContext = { apiBase: "https://optimizer.revefi.com", pending: null, canonicalHost };
const ok = (command: string, out: object): HookInput => ({ tool_input: { command }, tool_response: { stdout: JSON.stringify(out) } });
const failed = (command: string, out: object): HookInput => ({
  tool_input: { command },
  error: `Exit code 1\n${JSON.stringify(out)}\nThe analysis failed on the server.`,
});
const message = (input: HookInput, c = ctx) => {
  const cmd = hookCommand(input.tool_input?.command);
  return cmd && linkMessage(cmd, input, c);
};

describe("hookCommand", () => {
  it("knows the plugin's own commands, with an --api override", () => {
    expect(hookCommand("revefi-agent-analyzer login --start --json")).toEqual({ kind: "start" });
    expect(hookCommand("revefi-agent-analyzer upload '/p' --yes --json --no-wait")).toEqual({ kind: "upload" });
    expect(hookCommand("revefi-agent-analyzer status 'r1' --wait --json --api 'https://x.test'")).toEqual({ kind: "status", api: "https://x.test" });
    expect(hookCommand("revefi-agent-analyzer status r1 --api=https://x.test")).toEqual({ kind: "status", api: "https://x.test" });
  });

  it("refuses anything that could run or feed another program, and other commands", () => {
    for (const c of [
      "echo '{}'; revefi-agent-analyzer upload x",
      "revefi-agent-analyzer upload x && echo hi",
      "revefi-agent-analyzer upload x | cat",
      "revefi-agent-analyzer upload $(cat f)",
      "revefi-agent-analyzer upload `cat f`",
      "revefi-agent-analyzer upload x > out",
      "revefi-agent-analyzer upload x\necho hi",
      "FOO=1 revefi-agent-analyzer upload x",
      "revefi-agent-analyzer whoami --json",
      "revefi-agent-analyzer login --wait --json",
      "npm test",
    ]) {
      expect(hookCommand(c), c).toBeNull();
    }
  });
});

describe("linkMessage", () => {
  it("shows the sign-in link the CLI saved, not whatever was printed", () => {
    const start = ok("revefi-agent-analyzer login --start --json", { verification_uri_complete: "https://evil.test/x", user_code: "ZZZZ-ZZZZ" });
    expect(message(start, { ...ctx, pending: { verification_uri_complete: SIGN_IN, user_code: "ABCD-EFGH" } })).toBe(
      `Sign in to Revefi: open this link and check it shows the code ABCD-EFGH.\n${SIGN_IN}`,
    );
    expect(message(start)).toBeNull();
  });

  it("shows the report link after an upload, and when a run ends, even when the call failed", () => {
    expect(message(ok("revefi-agent-analyzer upload '/p' --yes --json --no-wait", { report_url: REPORT, phase: "analyzing" }))).toBe(
      `Your Revefi report (it fills in as the analysis runs):\n${REPORT}`,
    );
    expect(message(ok("revefi-agent-analyzer status 'r1' --wait --json", { report_url: REPORT, phase: "done" }))).toBe(
      `Your Revefi report is ready:\n${REPORT}`,
    );
    expect(message(failed("revefi-agent-analyzer status 'r1' --wait --json", { report_url: REPORT, phase: "failed" }))).toBe(
      `Your Revefi report:\n${REPORT}`,
    );
    // A failed call's progress lines (stderr) can come before its JSON line.
    const late = { tool_input: { command: "revefi-agent-analyzer status r1 --wait --json" }, error: `Exit code 1\nAnalyzing 40%\n${JSON.stringify({ report_url: REPORT, phase: "deferred" })}\nDeferred.` };
    expect(message(late)).toBe(`Your Revefi report:\n${REPORT}`);
  });

  it("stays quiet while a run is still going", () => {
    expect(message(ok("revefi-agent-analyzer status 'r1' --wait --json", { report_url: REPORT, phase: "analyzing" }))).toBeNull();
  });

  it("only shows a report link on the analyzer's own server", () => {
    const upload = (url: string) => ok("revefi-agent-analyzer upload x --json", { report_url: url });
    expect(message(upload("https://evil.test/r/abc"))).toBeNull();
    expect(message(upload("https://optimizer.revefi.com.evil.test/r/abc"))).toBeNull();
    expect(message(upload("https://user@optimizer.revefi.com/r/abc"))).toBeNull();
    expect(message(upload("https://analyzer.revefi.com/r/abc"))).toBe(`Your Revefi report (it fills in as the analysis runs):\nhttps://analyzer.revefi.com/r/abc`);
    expect(message(upload(`${REPORT}\u001b]8;;x\u0007`))).toBeNull();
  });

  it("only reads the CLI's own JSON line", () => {
    const cmd = "revefi-agent-analyzer upload x --json";
    expect(message({ tool_input: { command: cmd }, tool_response: { stdout: `noise\n${JSON.stringify({ report_url: REPORT })}` } })).toBeNull();
    expect(message({ tool_input: { command: cmd }, error: `not a failed call\n${JSON.stringify({ report_url: REPORT })}` })).toBeNull();
    expect(message({ tool_input: { command: cmd }, tool_response: { stdout: "not json" } })).toBeNull();
  });
});

describe("hook command", () => {
  const run = async (stdin: string, configDir = join(tmpdir(), "no-such-config"), env: NodeJS.ProcessEnv = {}) => {
    const out: string[] = [];
    const code = await main(["hook"], {
      io: { out: (s) => out.push(s), err: () => undefined },
      version: "0.1.0",
      cwd: "/",
      env,
      isTTY: false,
      ask: async () => false,
      configDir,
      readStdin: async () => stdin,
    });
    return { code, out: out.join("\n") };
  };

  it("prints the message as a systemMessage, and nothing (exit 0) for anything else", async () => {
    const shown = await run(JSON.stringify(ok("revefi-agent-analyzer upload x --json", { report_url: REPORT })));
    expect(shown).toEqual({ code: 0, out: JSON.stringify({ systemMessage: `Your Revefi report (it fills in as the analysis runs):\n${REPORT}` }) });
    expect(await run("garbage")).toEqual({ code: 0, out: "" });
  });

  it("takes the sign-in link from the pending sign-in the CLI saved", async () => {
    const dir = join(tmpdir(), `hook-${process.pid}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "pending-login.json"),
      JSON.stringify({ user_code: "ABCD-EFGH", verification_uri_complete: SIGN_IN, expires_at: Date.now() + 60_000, interval: 5, device_code: "d", config: {} }),
    );
    try {
      const r = await run(JSON.stringify(ok("revefi-agent-analyzer login --start --json", {})), dir);
      expect(JSON.parse(r.out)).toEqual({ systemMessage: `Sign in to Revefi: open this link and check it shows the code ABCD-EFGH.\n${SIGN_IN}` });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("speaks only for the server set in its own environment, never one named on the command line", async () => {
    const evil = ok("revefi-agent-analyzer upload x --json --api https://evil.test", { report_url: "https://evil.test/r/abc" });
    expect(await run(JSON.stringify(evil))).toEqual({ code: 0, out: "" });
    const dev = "https://dev-analyzer.revefi.com";
    const devUpload = ok(`revefi-agent-analyzer upload x --json --api ${dev}`, { report_url: `${dev}/r/abc` });
    expect(await run(JSON.stringify(devUpload))).toEqual({ code: 0, out: "" });
    const shown = await run(JSON.stringify(devUpload), undefined, { REVEFI_ANALYZER_API: dev });
    expect(JSON.parse(shown.out)).toEqual({ systemMessage: `Your Revefi report (it fills in as the analysis runs):\n${dev}/r/abc` });
  });

  it("isn't listed in the help", () => {
    expect(USAGE).not.toMatch(/^\s+hook\s/m);
  });
});

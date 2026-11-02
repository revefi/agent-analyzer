import { describe, expect, it } from "vitest";
import { linkMessage } from "../src/linkHook.js";
import { main, USAGE } from "../src/main.js";

const ok = (command: string, out: object) => ({ tool_input: { command }, tool_response: { stdout: JSON.stringify(out) } });
const failed = (command: string, out: object) => ({
  tool_input: { command },
  error: `Exit code 1\n${JSON.stringify(out)}\nThe analysis failed on the server.`,
});
const REPORT = "https://optimizer.revefi.com/r/abc";
const SIGN_IN = "https://auth.revefi.com/activate?user_code=ABCD-EFGH";

describe("linkMessage", () => {
  it("shows the sign-in link and code from login --start", () => {
    expect(linkMessage(ok("revefi-agent-analyzer login --start --json", { verification_uri_complete: SIGN_IN, user_code: "ABCD-EFGH" }))).toBe(
      `Sign in to Revefi: open this link and check it shows the code ABCD-EFGH.\n${SIGN_IN}`,
    );
  });

  it("shows the report link after an upload, and when a run ends, even when the call failed", () => {
    expect(linkMessage(ok("revefi-agent-analyzer upload '/p' --yes --json --no-wait", { report_url: REPORT, phase: "analyzing" }))).toBe(
      `Your Revefi report (it fills in as the analysis runs):\n${REPORT}`,
    );
    expect(linkMessage(ok("revefi-agent-analyzer status 'r1' --wait --json", { report_url: REPORT, phase: "done" }))).toBe(
      `Your Revefi report is ready:\n${REPORT}`,
    );
    expect(linkMessage(failed("revefi-agent-analyzer status 'r1' --wait --json", { report_url: REPORT, phase: "failed" }))).toBe(
      `Your Revefi report:\n${REPORT}`,
    );
  });

  it("stays quiet while a run is still going, and for other commands", () => {
    expect(linkMessage(ok("revefi-agent-analyzer status 'r1' --wait --json", { report_url: REPORT, phase: "analyzing" }))).toBeNull();
    expect(linkMessage(ok("revefi-agent-analyzer whoami --json", { email: "a@b.c" }))).toBeNull();
    expect(linkMessage(ok("revefi-agent-analyzer prepare --json", { preview_dir: "/p" }))).toBeNull();
    expect(linkMessage({ tool_input: { command: "revefi-agent-analyzer upload x" }, tool_response: { stdout: "not json" } })).toBeNull();
    expect(linkMessage({})).toBeNull();
  });

  it("refuses links or codes that could carry anything but a plain URL", () => {
    const start = "revefi-agent-analyzer login --start --json";
    expect(linkMessage(ok(start, { verification_uri_complete: `${SIGN_IN}\u001b]8;;x\u0007`, user_code: "ABCD-EFGH" }))).toBeNull();
    expect(linkMessage(ok(start, { verification_uri_complete: "javascript:alert(1)", user_code: "ABCD-EFGH" }))).toBeNull();
    expect(linkMessage(ok(start, { verification_uri_complete: SIGN_IN, user_code: "abcd efgh" }))).toBeNull();
    expect(linkMessage(ok("revefi-agent-analyzer upload x", { report_url: `${REPORT} trailing` }))).toBeNull();
  });
});

describe("hook command", () => {
  const run = async (stdin: string) => {
    const out: string[] = [];
    const code = await main(["hook"], {
      io: { out: (s) => out.push(s), err: () => undefined },
      version: "0.1.0",
      cwd: "/",
      env: {},
      isTTY: false,
      ask: async () => false,
      readStdin: async () => stdin,
    });
    return { code, out: out.join("\n") };
  };

  it("prints the message as a systemMessage, and nothing (exit 0) for anything else", async () => {
    const shown = await run(JSON.stringify(ok("revefi-agent-analyzer upload x --json", { report_url: REPORT })));
    expect(shown).toEqual({ code: 0, out: JSON.stringify({ systemMessage: `Your Revefi report (it fills in as the analysis runs):\n${REPORT}` }) });
    expect(await run("garbage")).toEqual({ code: 0, out: "" });
  });

  it("isn't listed in the help", () => {
    expect(USAGE).not.toMatch(/^\s+hook\s/m);
  });
});

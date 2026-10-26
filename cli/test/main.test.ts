import { describe, expect, it } from "vitest";
import type { Env } from "../src/commands.js";
import { main, USAGE } from "../src/main.js";

async function run(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const e: Env = {
    io: { out: (s) => out.push(s), err: (s) => err.push(s) },
    version: "1.2.3",
    cwd: "/",
    env: {},
    isTTY: false,
    ask: async () => false,
  };
  const code = await main(argv, e);
  return { code, out: out.join("\n"), err: err.join("\n") };
}

describe("main", () => {
  it("prints usage listing every command", async () => {
    const r = await run([]);
    expect(r).toEqual({ code: 0, out: USAGE, err: "" });
    for (const c of ["analyze", "prepare", "upload", "status", "recommendations", "feedback", "share", "delete-my-data"]) {
      expect(USAGE).toContain(`  ${c} `);
    }
  });

  it("prints the version", async () => {
    expect((await run(["--version"])).out).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("rejects an unknown flag or command on stderr with exit code 2", async () => {
    expect(await run(["--verison"])).toMatchObject({ code: 2, out: "" });
    const r = await run(["nope"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("Unknown command: nope");
  });

  it("rejects a bad flag value for a command with exit code 2", async () => {
    const r = await run(["prepare", "--days", "16"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--days must be a whole number from 1 to 15.");
  });
});

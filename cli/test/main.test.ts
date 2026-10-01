import { describe, expect, it } from "vitest";
import { main, USAGE } from "../src/main.js";

function run(argv: string[]): { code: number; out: string; err: string } {
  const out: string[] = [];
  const err: string[] = [];
  const code = main(argv, { out: (s) => out.push(s), err: (s) => err.push(s) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

describe("main", () => {
  it("prints usage with no command", () => {
    expect(run([])).toEqual({ code: 0, out: USAGE, err: "" });
  });

  it("prints the version", () => {
    expect(run(["--version"]).out).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("rejects an unknown flag on stderr with exit code 2", () => {
    const r = run(["--verison"]);
    expect(r.code).toBe(2);
    expect(r.out).toBe("");
    expect(r.err).toContain("--verison");
  });

  it("rejects an unknown command on stderr with exit code 2", () => {
    const r = run(["nope"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("Unknown command: nope");
  });
});

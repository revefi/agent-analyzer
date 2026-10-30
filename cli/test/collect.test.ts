import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  archivePath,
  collect,
  defaultProjectsDir,
  encodeProjectDir,
  MAX_UPLOAD_BYTES,
  pick,
  type Session,
  utcToday,
  windowEndingOn,
} from "../src/collect.js";

const ROOT = "/work/app";
let projectsDir: string;

function session(cwd: string, id: string, lines: (object | string)[]): string {
  const dir = join(projectsDir, encodeProjectDir(cwd));
  mkdirSync(dir, { recursive: true });
  const body = lines.map((l) => (typeof l === "string" ? l : JSON.stringify(l))).join("\n");
  writeFileSync(join(dir, `${id}.jsonl`), `${body}\n`);
  return dir;
}

const rec = (cwd: string, timestamp: string) => ({ type: "user", cwd, timestamp });

beforeAll(() => {
  projectsDir = mkdtempSync(join(tmpdir(), "collect-"));
  const app = session(ROOT, "s-in", [rec(ROOT, "2026-09-30T10:00:00Z"), rec(ROOT, "2026-09-30T11:00:00Z")]);
  mkdirSync(join(app, "s-in", "subagents"), { recursive: true });
  writeFileSync(join(app, "s-in", "subagents", "agent-a1.jsonl"), "{}\n");
  writeFileSync(join(app, "s-in", "subagents", "agent-a1.meta.json"), "{}");
  mkdirSync(join(app, "s-in", "tool-results"), { recursive: true });
  writeFileSync(join(app, "s-in", "tool-results", "toolu_1.txt"), "raw tool output stays local");
  session(ROOT, "s-start-edge", [rec(ROOT, "2026-09-25T00:00:00Z")]);
  session(ROOT, "s-torn-first", ['{"type":"us', rec(ROOT, "2026-09-26T10:00:00Z")]);
  session(ROOT, "s-no-cwd", [{ type: "user", timestamp: "2026-09-27T10:00:00Z" }]);
  session("/work/app-old", "s-sibling-no-cwd", [{ type: "user", timestamp: "2026-09-27T10:00:00Z" }]);
  session(ROOT, "s-old", [rec(ROOT, "2026-09-01T10:00:00Z")]);
  session(ROOT, "s-crosses", [rec(ROOT, "2026-09-24T23:59:00Z"), rec(ROOT, "2026-09-25T00:30:00Z")]);
  session(ROOT, "s-late-ts", [{ type: "summary" }, rec(ROOT, "2026-10-01T08:00:00Z")]);
  session(ROOT, "s-torn", [rec(ROOT, "2026-10-01T09:00:00Z"), '{"type":"assis']);
  session(ROOT, "s-skip-me", [rec(ROOT, "2026-10-01T09:00:00Z")]);
  session(ROOT, "s-no-ts", [{ type: "summary" }]);
  session(`${ROOT}/.claude/worktrees/w1`, "s-worktree", [rec(`${ROOT}/.claude/worktrees/w1`, "2026-09-29T10:00:00Z")]);
  session(`${ROOT}/ui`, "s-subdir", [rec(`${ROOT}/ui`, "2026-09-29T10:00:00Z")]);
  session("/work/app-old", "s-sibling", [rec("/work/app-old", "2026-09-29T10:00:00Z")]);
  writeFileSync(join(projectsDir, encodeProjectDir(ROOT), "notes.txt"), "not a session");
  mkdirSync(join(projectsDir, encodeProjectDir(ROOT), "dir.jsonl"));
});

afterAll(() => rmSync(projectsDir, { recursive: true, force: true }));

const ids = (r: Awaited<ReturnType<typeof collect>>) => r.sessions.map((s) => s.id).sort();

describe("collect", () => {
  const base = () => ({ projectsDir, days: 7, today: "2026-10-01" });

  it("keeps sessions whose first record falls in the window, under the root, its worktrees and subdirs", async () => {
    const r = await collect({ ...base(), root: ROOT, exclude: ["s-skip"] });
    expect(r.window).toEqual({ days: 7, start: "2026-09-25", end: "2026-10-01" });
    expect(ids(r)).toEqual([
      "s-in",
      "s-late-ts",
      "s-no-cwd",
      "s-start-edge",
      "s-subdir",
      "s-torn",
      "s-torn-first",
      "s-worktree",
    ]);
  });

  it("does not treat a look-alike sibling folder as part of the root", async () => {
    expect(ids(await collect({ ...base(), root: ROOT }))).not.toContain("s-sibling");
  });

  it("falls back to the folder name only when a session never recorded a cwd", async () => {
    expect(ids(await collect({ ...base(), root: ROOT }))).not.toContain("s-sibling-no-cwd");
  });

  it("covers every project when no root is given", async () => {
    expect(ids(await collect(base()))).toContain("s-sibling");
  });

  it("ignores an empty exclude prefix instead of excluding everything", async () => {
    expect(ids(await collect({ ...base(), root: ROOT, exclude: [""] }))).toContain("s-in");
  });

  it("returns nothing when Claude Code has never run", async () => {
    expect((await collect({ ...base(), projectsDir: join(projectsDir, "missing") })).sessions).toEqual([]);
  });

  it.skipIf(process.platform === "win32")("closes every transcript it opens", async () => {
    // Other test files share this process's descriptor table, so allow a little noise; a leak
    // would add one descriptor per transcript per run (over a hundred here).
    const before = readdirSync("/dev/fd").length;
    for (let i = 0; i < 10; i++) await collect(base());
    expect(readdirSync("/dev/fd").length - before).toBeLessThan(10);
  });

  it("reaches back for the most recent sessions when the window has too few", async () => {
    const opts = { ...base(), root: ROOT, exclude: ["s-skip"] };
    const nine = await collect({ ...opts, minSessions: 9 });
    expect(nine.window).toEqual({ days: 8, start: "2026-09-24", end: "2026-10-01" });
    expect(ids(nine)).toContain("s-crosses");
    expect(ids(nine)).not.toContain("s-old");
    const ten = await collect({ ...opts, minSessions: 10 });
    expect(ten.window).toEqual({ days: 31, start: "2026-09-01", end: "2026-10-01" });
    expect(ten.sessions).toHaveLength(10);
  });

  it("uploads only the subagent folder, transcript first, never tool-results", async () => {
    const r = await collect({ ...base(), root: ROOT });
    const s = r.sessions.find((x) => x.id === "s-in");
    expect(s?.files.map((f) => archivePath(projectsDir, f))).toEqual([
      "projects/-work-app/s-in.jsonl",
      "projects/-work-app/s-in/subagents/agent-a1.jsonl",
      "projects/-work-app/s-in/subagents/agent-a1.meta.json",
    ]);
    expect(s?.bytes).toBeGreaterThan(0);
  });
});

describe("pick", () => {
  const s = (id: string, day: string): Session => ({ project: "p", id, day, files: [], bytes: 1 });
  const all = [s("a", "2026-10-01"), s("b", "2026-09-20"), s("c", "2026-09-20"), s("d", "2026-08-01")];
  const ids = (r: ReturnType<typeof pick>) => r.sessions.map((x) => x.id);

  it("keeps the window when it already holds the floor", () => {
    expect(pick(all, "2026-10-01", 7, 1)).toEqual({ window: windowEndingOn("2026-10-01", 7), sessions: [all[0]] });
  });

  it("takes the newest sessions past the window, widening it to their span, in their original order", () => {
    const r = pick(all, "2026-10-01", 7, 2);
    expect(ids(r)).toEqual(["a", "b"]);
    expect(r.window).toEqual({ days: 12, start: "2026-09-20", end: "2026-10-01" });
    expect(ids(pick(all, "2026-10-01", 7, 10))).toEqual(["a", "b", "c", "d"]);
  });

  it("keeps the newest sessions that fit in the upload limit, and always the newest one", () => {
    const big = (id: string, day: string): Session => ({ ...s(id, day), bytes: MAX_UPLOAD_BYTES / 2 });
    const r = pick([big("a", "2026-10-01"), big("b", "2026-09-30"), big("c", "2026-09-29")], "2026-10-01", 7, 1);
    expect(ids(r)).toEqual(["a", "b"]);
    expect(r.window).toEqual({ days: 2, start: "2026-09-30", end: "2026-10-01" });
    const widened = pick([big("a", "2026-10-01"), big("b", "2026-09-01"), big("c", "2026-08-01")], "2026-10-01", 7, 3);
    expect(ids(widened)).toEqual(["a", "b"]);
    expect(widened.window).toEqual({ days: 31, start: "2026-09-01", end: "2026-10-01" });
    expect(ids(pick([{ ...s("huge", "2026-10-01"), bytes: MAX_UPLOAD_BYTES * 2 }, s("x", "2026-09-30")], "2026-10-01", 7, 1))).toEqual(["huge"]);
  });

  it("keeps the window when there is nothing older to add", () => {
    expect(pick(all.slice(0, 1), "2026-10-01", 15, 15).window.days).toBe(15);
    expect(pick([], "2026-10-01", 15, 15)).toEqual({ window: windowEndingOn("2026-10-01", 15), sessions: [] });
  });
});

describe("helpers", () => {
  it("encodes a cwd the way Claude Code names project folders", () => {
    expect(encodeProjectDir("/Users/me/repo/.claude/worktrees/x_y")).toBe("-Users-me-repo--claude-worktrees-x-y");
  });

  it("rejects a window that is not a whole number of days", () => {
    expect(() => windowEndingOn("2026-10-01", 0)).toThrow(RangeError);
    expect(() => windowEndingOn("2026-10-01", Number.NaN)).toThrow(RangeError);
    expect(() => windowEndingOn("Oct 1", 7)).toThrow(RangeError);
  });

  it("computes an inclusive window across a month boundary", () => {
    expect(windowEndingOn("2026-03-02", 3)).toEqual({ days: 3, start: "2026-02-28", end: "2026-03-02" });
  });

  it("uses the UTC date", () => {
    expect(utcToday(new Date("2026-10-01T23:30:00-07:00"))).toBe("2026-10-02");
  });

  it("honours CLAUDE_CONFIG_DIR", () => {
    expect(defaultProjectsDir({ CLAUDE_CONFIG_DIR: "/cfg" })).toBe("/cfg/projects");
  });
});

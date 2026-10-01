import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { list } from "tar";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { collect, encodeProjectDir, type Session } from "../src/collect.js";
import { buildManifest, LIMITS, limitProblem, pack, type Packed } from "../src/pack.js";
import { PREVIEW_META, PreviewError, type PreviewMeta, readPreview, renderReport, REPORT_FILE, writePreview } from "../src/preview.js";
import { validateManifest } from "./contract.js";

const HOME = "/home/dev";
const ROOT = `${HOME}/app`;
const ALIAS = "~-app";
const SECRET = ["gh", "p_", "B".repeat(36)].join("");
const posix = process.platform !== "win32";
let tmp: string;
let projectsDir: string;
let sessions: Session[];
let preview: Awaited<ReturnType<typeof writePreview>>;
let archive: string;
let packed: Packed;

const line = (o: object) => `${JSON.stringify(o)}\n`;

beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), "pack-"));
  projectsDir = join(tmp, "claude", "projects");
  const proj = join(projectsDir, encodeProjectDir(ROOT));
  mkdirSync(join(proj, "s1", "subagents"), { recursive: true });
  mkdirSync(join(proj, "s1", "tool-results"), { recursive: true });
  const big = "lorem ipsum ".repeat(20_000);
  writeFileSync(
    join(proj, "s1.jsonl"),
    line({ type: "user", cwd: ROOT, timestamp: "2026-09-30T10:00:00Z", message: { content: `push with ${SECRET}` } }) +
      line({ type: "assistant", cwd: ROOT, timestamp: "2026-09-30T10:01:00Z", message: { content: `ls ${ROOT}/src` } }) +
      Array.from({ length: 40 }, () => line({ type: "assistant", message: { content: big } })).join(""),
  );
  writeFileSync(join(proj, "s1", "subagents", "agent-a1.jsonl"), line({ type: "assistant", isSidechain: true }));
  writeFileSync(join(proj, "s1", "subagents", "agent-a1.meta.json"), JSON.stringify({ agentType: "Explore" }));
  writeFileSync(join(proj, "s1", "tool-results", "toolu_1.txt"), SECRET);
  writeFileSync(join(proj, "s2.jsonl"), line({ type: "user", cwd: ROOT, timestamp: "2026-09-29T10:00:00Z" }));

  ({ sessions } = await collect({ projectsDir, root: ROOT, days: 7, today: "2026-10-01" }));
  // s2 is deleted by Claude Code after it was found but before the preview reads it.
  rmSync(join(proj, "s2.jsonl"));
  mkdirSync(join(tmp, "repo", ".revefi"), { recursive: true });
  writeFileSync(join(tmp, "repo", ".revefi", ".gitignore"), "# mine\n*\n");
  preview = await writePreview({
    projectsDir,
    window: { days: 7, start: "2026-09-25", end: "2026-10-01" },
    sessions,
    revefiDir: join(tmp, "repo", ".revefi"),
    home: HOME,
    now: new Date("2026-10-01T12:00:00Z"),
  });
  // Things a file browser or the user may leave in the folder must not be uploaded.
  writeFileSync(join(preview.dir, "projects", ".DS_Store"), "junk");
  if (posix) symlinkSync("/etc/hosts", join(preview.dir, "projects", ALIAS, "linked"));
  archive = join(tmp, "upload.tar.gz");
  packed = await pack(preview.dir, preview.meta, archive);
});

afterAll(() => rmSync(tmp, { recursive: true, force: true }));

async function entries(): Promise<{ path: string; size: number; uname?: string; uid?: number }[]> {
  const out: { path: string; size: number; uname?: string; uid?: number }[] = [];
  await list({ file: archive, onReadEntry: (e) => out.push({ path: e.path, size: e.size, uname: e.uname, uid: e.uid }) });
  return out;
}

describe("writePreview", () => {
  it("writes redacted copies under the home alias, in a unique private folder", () => {
    expect(preview.dir.startsWith(join(tmp, "repo", ".revefi", "upload-preview", "2026-10-01T12-00-00-000Z-"))).toBe(true);
    const copy = readFileSync(join(preview.dir, "projects", ALIAS, "s1.jsonl"), "utf8");
    expect(copy).not.toContain(SECRET);
    expect(copy).toContain("<GITHUB_TOKEN>");
    expect(copy).toContain("ls ~/app/src");
    expect(copy).not.toContain(HOME);
    if (posix) {
      expect(statSync(preview.dir).mode & 0o077).toBe(0);
      expect(statSync(join(preview.dir, "projects", ALIAS, "s1.jsonl")).mode & 0o077).toBe(0);
    }
  });

  it("keeps an existing .revefi/.gitignore", () => {
    expect(readFileSync(join(tmp, "repo", ".revefi", ".gitignore"), "utf8")).toBe("# mine\n*\n");
  });

  it("leaves out a session that vanished, and records exactly what will be sent", async () => {
    const meta = await readPreview(preview.dir);
    expect(meta.sessions).toEqual([
      expect.objectContaining({
        project: ALIAS,
        id: "s1",
        day: "2026-09-30",
        counts: { "github-token": 1, "home-path": 3 },
        paths: [
          `projects/${ALIAS}/s1.jsonl`,
          `projects/${ALIAS}/s1/subagents/agent-a1.jsonl`,
          `projects/${ALIAS}/s1/subagents/agent-a1.meta.json`,
        ],
      }),
    ]);
  });

  it("tells the user what is sent as written, not only what was removed", () => {
    const report = readFileSync(join(preview.dir, REPORT_FILE), "utf8");
    expect(report).toContain("## Sent as written");
    expect(report).toContain("| GitHub tokens | 1 |");
    expect(report).toContain("--exclude-session");
    const empty: PreviewMeta = { window: preview.meta.window, sessions: [], counts: {}, bytes: 0 };
    expect(renderReport(empty)).toContain("No known secret formats were found. Everything else is still sent as written.");
  });

  it("removes the half-written folder when it fails", async () => {
    const revefiDir = join(tmp, "fail", ".revefi");
    const broken: Session = { project: "p", id: "x", day: "2026-09-30", files: [join(tmp, "is-a-dir.jsonl")], bytes: 1 };
    mkdirSync(broken.files[0] ?? "", { recursive: true });
    await expect(
      writePreview({ projectsDir: tmp, window: preview.meta.window, sessions: [broken], revefiDir }),
    ).rejects.toThrow();
    expect(() => readFileSync(join(revefiDir, "upload-preview"))).toThrow();
    const left = (await import("node:fs")).readdirSync(join(revefiDir, "upload-preview"));
    expect(left).toEqual([]);
  });
});

describe("pack", () => {
  it("archives exactly the recorded files: no junk, no symlinks, no tool-results", async () => {
    expect((await entries()).map((e) => e.path).sort()).toEqual([
      `projects/${ALIAS}/s1.jsonl`,
      `projects/${ALIAS}/s1/subagents/agent-a1.jsonl`,
      `projects/${ALIAS}/s1/subagents/agent-a1.meta.json`,
    ]);
  });

  it("puts no user name, ids or home path in the tar", async () => {
    for (const e of await entries()) {
      expect(e.uname ?? "").toBe("");
      expect(e.uid ?? 0).toBe(0);
      expect(e.path).not.toContain(encodeProjectDir(HOME));
    }
    if (posix) expect(statSync(archive).mode & 0o077).toBe(0);
  });

  it("produces a manifest the server's schema accepts, with sizes matching the archive", async () => {
    const sizes = (await entries()).reduce((a, e) => a + e.size, 0);
    expect(packed.uncompressed).toBe(sizes);
    const m = buildManifest(preview.meta, packed, { name: "plugin", version: "0.1.0" });
    expect(validateManifest(m), JSON.stringify(validateManifest.errors)).toBe(true);
    expect(m.session_count).toBe(1);
    expect(m.bytes.compressed).toBe(statSync(archive).size);
    expect(limitProblem(m)).toBeUndefined();
  });
});

describe("limitProblem", () => {
  const ok = {
    window: { days: 7, start: "2026-09-25", end: "2026-10-01" },
    session_count: 3,
    bytes: { compressed: LIMITS.maxCompressedBytes, uncompressed: LIMITS.maxUncompressedBytes },
  };

  it("allows exactly the limits", () => {
    expect(limitProblem(ok)).toBeUndefined();
  });

  it("checks the window before emptiness, and only suggests a longer window when allowed", () => {
    expect(limitProblem({ ...ok, session_count: 0, window: { ...ok.window, days: 30 } })).toMatch(/--days 7 or fewer/);
    expect(limitProblem({ ...ok, session_count: 0 })).toBe(
      "No Claude Code sessions started between 2026-09-25 and 2026-10-01 here. Try --all-projects.",
    );
    expect(limitProblem({ ...ok, session_count: 0, window: { days: 3, start: "2026-09-29", end: "2026-10-01" } })).toMatch(
      /--all-projects or --days 7\.$/,
    );
  });

  it("names the limit that was exceeded and how to get under it", () => {
    expect(limitProblem({ ...ok, bytes: { compressed: LIMITS.maxCompressedBytes + 1, uncompressed: 1 } })).toBe(
      "The upload is 200.0 MB compressed; the limit is 200.0 MB. Use a shorter --days, or leave out the largest " +
        "sessions (listed first in REDACTION_REPORT.md) with --exclude-session.",
    );
    expect(limitProblem({ ...ok, bytes: { compressed: 1, uncompressed: LIMITS.maxUncompressedBytes * 1.5 } })).toMatch(
      /^The upload is 3\.0 GB before compression; the limit is 2\.0 GB\./,
    );
  });
});

describe("a preview that was tampered with or changed", () => {
  const copy = () => {
    const dir = mkdtempSync(join(tmp, "tamper-"));
    cpSync(preview.dir, dir, { recursive: true });
    return dir;
  };
  const withPaths = (dir: string, paths: string[]) => {
    const meta = JSON.parse(readFileSync(join(dir, PREVIEW_META), "utf8")) as PreviewMeta;
    meta.sessions[0] = { ...(meta.sessions[0] as PreviewMeta["sessions"][number]), paths };
    writeFileSync(join(dir, PREVIEW_META), JSON.stringify(meta));
  };

  it.each([["../../.ssh/id_rsa"], ["/etc/hosts"], [`projects/${ALIAS}/../../../x`], ["projects/a\\b"], ["README.md"]])(
    "refuses a listed path outside projects/: %s",
    async (bad) => {
      const dir = copy();
      withPaths(dir, [`projects/${ALIAS}/s1.jsonl`, bad]);
      await expect(readPreview(dir)).rejects.toThrow(PreviewError);
    },
  );

  it.skipIf(!posix)("refuses a folder in the preview that links outside it", async () => {
    const dir = copy();
    rmSync(join(dir, "projects", ALIAS), { recursive: true });
    symlinkSync(join(tmp, "claude", "projects", encodeProjectDir(ROOT)), join(dir, "projects", ALIAS));
    await expect(pack(dir, await readPreview(dir), join(tmp, "x.tar.gz"))).rejects.toThrow(/points outside the preview folder/);
  });

  it("says what to do when a previewed file was deleted", async () => {
    const dir = copy();
    rmSync(join(dir, "projects", ALIAS, "s1", "subagents", "agent-a1.jsonl"));
    await expect(pack(dir, await readPreview(dir), join(tmp, "y.tar.gz"))).rejects.toThrow(
      /agent-a1\.jsonl was removed from the preview, so nothing was uploaded\. Run `prepare` again/,
    );
  });

  it("explains a missing or damaged preview", async () => {
    await expect(readPreview(join(tmp, "nope"))).rejects.toThrow(/^No preview at .*Previews are removed once uploaded/);
    const dir = copy();
    writeFileSync(join(dir, PREVIEW_META), "{not json");
    await expect(readPreview(dir)).rejects.toThrow(/is damaged\. Run `prepare` again\./);
  });
});

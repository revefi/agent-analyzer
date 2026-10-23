import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { list } from "tar";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyErrorPicks, parsePicks } from "../src/errorpick.js";
import { pack } from "../src/pack.js";
import { ERROR_CANDIDATES, PREVIEW_META, PreviewError, type PreviewMeta, REPORT_FILE, writePreview } from "../src/preview.js";

const line = (o: object) => `${JSON.stringify(o)}\n`;
const OUTPUT = [
  "Exit code 1",
  ...Array.from({ length: 300 }, (_, i) => `waiting for element ${i}`),
  "page.click: Timeout 30000ms exceeded.",
  ...Array.from({ length: 30 }, (_, i) => `  - retry ${i}`),
  "Node.js v24.18.0",
].join("\n");

let tmp: string;
let dir: string;
let transcript: string;

const sent = () =>
  readFileSync(transcript, "utf8")
    .trim()
    .split("\n")
    .flatMap((l) => (JSON.parse(l).message?.content ?? []) as Record<string, unknown>[])
    .filter((b) => b.type === "tool_result");

beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), "errorpick-"));
  const proj = join(tmp, "projects", "-app");
  mkdirSync(proj, { recursive: true });
  const src = join(proj, "s1.jsonl");
  writeFileSync(
    src,
    line({ type: "user", timestamp: "2026-10-01T10:00:00Z", message: { content: "run the e2e test" } }) +
      line({ type: "user", message: { content: [{ type: "tool_result", tool_use_id: "ok1", content: "secret file body" }] } }) +
      line({ type: "user", message: { content: [{ type: "tool_result", tool_use_id: "bad1", is_error: true, content: OUTPUT }] } }),
  );
  const preview = await writePreview({
    projectsDir: join(tmp, "projects"),
    window: { days: 1, start: "2026-10-01", end: "2026-10-01" },
    sessions: [{ project: "-app", id: "s1", day: "2026-10-01", files: [src], bytes: 0 }],
    revefiDir: join(tmp, ".revefi"),
  });
  dir = preview.dir;
  transcript = join(dir, "projects", "-app", "s1.jsonl");
});

afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("error candidates", () => {
  it("keeps the failed call's redacted lines on this machine only, head and tail", async () => {
    const file = join(dir, ERROR_CANDIDATES);
    if (process.platform !== "win32") expect(statSync(file).mode & 0o777).toBe(0o600);
    const { candidates } = JSON.parse(readFileSync(file, "utf8"));
    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({ id: "bad1", file: "projects/-app/s1.jsonl" });
    expect(candidates[0].lines).toHaveLength(250);
    expect(candidates[0].lines[0]).toBe("Exit code 1");
    expect(candidates[0].lines.at(-1)).toBe("Node.js v24.18.0");
    const packedPaths: string[] = [];
    const meta = JSON.parse(readFileSync(join(dir, PREVIEW_META), "utf8")) as PreviewMeta;
    const archive = join(tmp, "out.tar.gz");
    await pack(dir, meta, archive);
    await list({ file: archive, onReadEntry: (e) => packedPaths.push(e.path) });
    expect(packedPaths.some((p) => p.includes(ERROR_CANDIDATES))).toBe(false);
    expect(meta.error_messages).toEqual({ failed: 1, picked_by_model: 0 });
  });

  it("sends the fixed rule's message until lines are picked, and nothing for a successful call", () => {
    const [ok, bad] = sent();
    expect(ok?.content).toBe("");
    expect(String(bad?.content).split("\n")[0]).toBe("Exit code 1");
  });
});

describe("applyErrorPicks", () => {
  it("uses the chosen lines, ignores unknown ids and out-of-range numbers, and updates the report", async () => {
    const { candidates } = JSON.parse(readFileSync(join(dir, ERROR_CANDIDATES), "utf8"));
    const timeout = (candidates[0].lines as string[]).indexOf("page.click: Timeout 30000ms exceeded.") + 1;
    const before = JSON.parse(readFileSync(join(dir, PREVIEW_META), "utf8")) as PreviewMeta;
    const r = await applyErrorPicks(dir, { bad1: [timeout, 9999, 0], ok1: [1], nope: [1] });
    expect(r).toEqual({ applied: 1, ignored: ["ok1", "nope"] });
    const [ok, bad] = sent();
    expect(ok?.content).toBe("");
    expect(bad?.content).toBe("page.click: Timeout 30000ms exceeded.");
    const meta = JSON.parse(readFileSync(join(dir, PREVIEW_META), "utf8")) as PreviewMeta;
    expect(meta.error_messages).toEqual({ failed: 1, picked_by_model: 1 });
    expect(meta.bytes).toBe(statSync(transcript).size);
    expect(meta.bytes).toBeLessThan(before.bytes);
    expect(readFileSync(join(dir, REPORT_FILE), "utf8")).toContain("Claude Haiku");
  });

  it("caps a pick at 6 lines", async () => {
    await applyErrorPicks(dir, { bad1: Array.from({ length: 50 }, (_, i) => i + 1) });
    expect(String(sent()[1]?.content).split("\n")).toHaveLength(6);
  });

  it("rejects picks that aren't id-to-line-number JSON", () => {
    expect(() => parsePicks("not json")).toThrow(PreviewError);
    expect(() => parsePicks('{"bad1": ["1"]}')).toThrow(PreviewError);
    expect(() => parsePicks("[1, 2]")).toThrow(PreviewError);
    expect(parsePicks('{"bad1": [1, 3]}')).toEqual({ bad1: [1, 3] });
  });
});

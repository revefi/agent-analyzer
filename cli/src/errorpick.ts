import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  ERROR_CANDIDATES,
  type FileErrorCandidate,
  PREVIEW_META,
  PreviewError,
  readPreview,
  renderReport,
  REPORT_FILE,
} from "./preview.js";
import { messageFrom } from "./redact.js";

/** Line numbers, 1-based as the model saw them, keyed by `tool_use_id`. */
export type ErrorPicks = Record<string, number[]>;

export interface PickResult {
  /** Error messages rewritten from the chosen lines. */
  applied: number;
  /** Ids that weren't failed calls in this preview, or came with no usable line numbers. */
  ignored: string[];
}

/** Parses `{"<tool_use_id>": [line numbers]}`; anything else is rejected rather than guessed at. */
export function parsePicks(text: string): ErrorPicks {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PreviewError('The picks aren\'t JSON. Expected {"<tool_use_id>": [line numbers]}.');
  }
  const ok =
    typeof parsed === "object" &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    Object.values(parsed).every((v) => Array.isArray(v) && v.every((n) => Number.isInteger(n)));
  if (!ok) throw new PreviewError('Expected {"<tool_use_id>": [line numbers]}, with whole numbers only.');
  return parsed as ErrorPicks;
}

async function readCandidates(dir: string): Promise<FileErrorCandidate[]> {
  let text: string;
  try {
    text = await readFile(join(dir, ERROR_CANDIDATES), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const parsed = JSON.parse(text) as { candidates?: FileErrorCandidate[] };
  return Array.isArray(parsed.candidates) ? parsed.candidates : [];
}

/** Rewrites the chosen failed calls' messages in one transcript; returns how many it changed. */
function rewrite(text: string, chosen: Map<string, string>): { text: string; changed: number } {
  let changed = 0;
  const lines = text.split("\n").map((line) => {
    if (!line) return line;
    const rec = JSON.parse(line) as { message?: { content?: unknown } };
    const content = rec.message?.content;
    if (!Array.isArray(content)) return line;
    let hit = false;
    for (const block of content as Record<string, unknown>[]) {
      const id = block?.tool_use_id;
      if (block?.type === "tool_result" && block.is_error === true && typeof id === "string" && chosen.has(id)) {
        block.content = chosen.get(id);
        hit = true;
        changed++;
      }
    }
    return hit ? JSON.stringify(rec) : line;
  });
  return { text: lines.join("\n"), changed };
}

/**
 * Replaces the fixed rule's error message with the chosen lines for each picked failed call. The
 * lines come from the preview's own redacted copy and pass the same 6-line, 500-character cap, so
 * a pick can only choose among lines of an error that is already being sent.
 */
export async function applyErrorPicks(dir: string, picks: ErrorPicks): Promise<PickResult> {
  const meta = await readPreview(dir);
  const candidates = await readCandidates(dir);
  const byId = new Map(candidates.map((c) => [c.id, c]));
  const chosen = new Map<string, string>();
  const ignored: string[] = [];
  for (const [id, numbers] of Object.entries(picks)) {
    const c = byId.get(id);
    const indexes = c ? numbers.filter((n) => n >= 1 && n <= c.lines.length).map((n) => n - 1) : [];
    const message = c && indexes.length ? messageFrom(c.lines, indexes) : "";
    if (message) chosen.set(id, message);
    else ignored.push(id);
  }
  const files = new Set([...chosen.keys()].map((id) => byId.get(id)?.file ?? ""));
  let applied = 0;
  for (const session of meta.sessions) {
    for (const file of session.paths.filter((p) => files.has(p))) {
      const path = join(dir, ...file.split("/"));
      const before = await readFile(path, "utf8");
      const { text, changed } = rewrite(before, chosen);
      if (!changed) continue;
      await writeFile(path, text, { mode: 0o600 });
      const delta = Buffer.byteLength(text) - Buffer.byteLength(before);
      session.bytes += delta;
      meta.bytes += delta;
      applied += changed;
    }
  }
  meta.error_messages = { failed: meta.error_messages?.failed ?? candidates.length, picked_by_model: applied };
  await writeFile(join(dir, PREVIEW_META), `${JSON.stringify(meta, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(dir, REPORT_FILE), renderReport(meta), { mode: 0o600 });
  return { applied, ignored };
}

import { createReadStream } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative, sep } from "node:path";
import { createInterface } from "node:readline";

export interface Window {
  days: number;
  start: string;
  end: string;
}

export interface Session {
  project: string;
  id: string;
  day: string;
  /** Where the session started, as Claude Code recorded it; absent in very old transcripts. */
  cwd?: string;
  /** Absolute paths: the transcript first, then its subagent transcripts and their metadata. */
  files: string[];
  bytes: number;
}

export interface CollectOptions {
  projectsDir: string;
  /** Keep only sessions run in this directory or below it; all projects when omitted. */
  root?: string;
  days: number;
  today: string;
  exclude?: string[];
  /** Reach back past `days` for this many of the most recent sessions; see `pick`. */
  minSessions?: number;
}

/** How far back `minSessions` reaches: the most days an upload manifest may span. */
export const MAX_LOOKBACK_DAYS = 90;

export function defaultProjectsDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"), "projects");
}

/** Claude Code names a project folder after its cwd with every non-alphanumeric turned into `-`. */
export function encodeProjectDir(cwd: string): string {
  return cwd.replace(/[^A-Za-z0-9]/g, "-");
}

export function utcToday(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export function windowEndingOn(today: string, days: number): Window {
  if (!Number.isInteger(days) || days < 1) throw new RangeError(`days must be a whole number of at least 1, got ${days}`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(today)) throw new RangeError(`today must be YYYY-MM-DD, got ${today}`);
  const start = new Date(`${today}T00:00:00Z`);
  start.setUTCDate(start.getUTCDate() - (days - 1));
  return { days, start: start.toISOString().slice(0, 10), end: today };
}

const foldCase = process.platform === "win32" ? (s: string) => s.toLowerCase() : (s: string) => s;

/** The session's day is the UTC date of its first timestamped record, as the server's window stage reads it. */
async function readHead(file: string, needCwd: boolean, window: Window): Promise<{ day?: string; cwd?: string }> {
  const input = createReadStream(file, "utf8");
  const lines = createInterface({ input, crlfDelay: Infinity });
  const head: { day?: string; cwd?: string } = {};
  try {
    for await (const line of lines) {
      if (!line.trim()) continue;
      let rec: unknown;
      try {
        rec = JSON.parse(line);
      } catch {
        continue; // A torn line is normal in a live session; the next line decides.
      }
      if (typeof rec !== "object" || rec === null) continue;
      const r = rec as Record<string, unknown>;
      if (!head.day && typeof r.timestamp === "string" && r.timestamp) head.day = r.timestamp.slice(0, 10);
      if (!head.cwd && typeof r.cwd === "string") head.cwd = r.cwd;
      if (head.day && (head.day < window.start || head.day > window.end)) break;
      if (head.day && (head.cwd || !needCwd)) break;
    }
  } finally {
    lines.close();
    input.destroy();
  }
  return head;
}

const SUBAGENT_FILE = /^agent-.+\.(?:jsonl|meta\.json)$/;

/** Only `subagents/` is uploaded; `tool-results/` and anything else in the session folder stays local. */
async function subagentFiles(sessionDir: string): Promise<string[]> {
  const dir = join(sessionDir, "subagents");
  const entries = await readdir(dir, { withFileTypes: true }).catch(ignoreMissing);
  return entries
    .filter((e) => e.isFile() && SUBAGENT_FILE.test(e.name))
    .map((e) => join(dir, e.name))
    .sort();
}

function ignoreMissing(err: NodeJS.ErrnoException): never[] {
  if (err.code === "ENOENT" || err.code === "ENOTDIR") return [];
  throw err;
}

function isVanished(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "EISDIR";
}

/** Whether a session that started in cwd counts as inside root, as `--project root` scans it. */
export function inRoot(cwd: string | undefined, root: string, project: string): boolean {
  if (cwd === undefined) return foldCase(project) === foldCase(encodeProjectDir(root));
  const [c, r] = [foldCase(cwd), foldCase(root)];
  return c === r || c.startsWith(r.endsWith(sep) ? r : r + sep);
}

async function readSession(
  projectsDir: string,
  project: string,
  id: string,
  opts: CollectOptions,
  window: Window,
): Promise<Session | undefined> {
  const transcript = join(projectsDir, project, `${id}.jsonl`);
  const info = await stat(transcript);
  // The first record can't be newer than the file's last write.
  if (info.mtime.toISOString().slice(0, 10) < window.start) return undefined;
  const head = await readHead(transcript, true, window);
  if (!head.day || head.day < window.start || head.day > window.end) return undefined;
  if (opts.root !== undefined && !inRoot(head.cwd, opts.root, project)) return undefined;
  const subs = await subagentFiles(join(projectsDir, project, id));
  const sizes = await Promise.all(subs.map(async (f) => (await stat(f)).size));
  return {
    project,
    id,
    day: head.day,
    cwd: head.cwd,
    files: [transcript, ...subs],
    bytes: sizes.reduce((a, b) => a + b, info.size),
  };
}

export async function collect(opts: CollectOptions): Promise<{ window: Window; sessions: Session[] }> {
  const floor = opts.minSessions ?? 0;
  const window = windowEndingOn(opts.today, floor > 0 ? MAX_LOOKBACK_DAYS : opts.days);
  const exclude = (opts.exclude ?? []).filter((x) => x.length > 0);
  // Long folder names may be truncated by Claude Code; the recorded cwd stays authoritative.
  const prefix = opts.root === undefined ? "" : foldCase(encodeProjectDir(opts.root).slice(0, 200));
  const projects = (await readdir(opts.projectsDir, { withFileTypes: true }).catch(ignoreMissing))
    .filter((e) => e.isDirectory() && foldCase(e.name).startsWith(prefix))
    .map((e) => e.name)
    .sort();

  const sessions: Session[] = [];
  for (const project of projects) {
    const entries = await readdir(join(opts.projectsDir, project), { withFileTypes: true }).catch(ignoreMissing);
    const ids = entries
      .filter((e) => e.isFile() && e.name.endsWith(".jsonl"))
      .map((e) => e.name.slice(0, -".jsonl".length))
      .filter((id) => !exclude.some((x) => id.startsWith(x)))
      .sort();
    for (const id of ids) {
      try {
        const s = await readSession(opts.projectsDir, project, id, opts, window);
        if (s) sessions.push(s);
      } catch (err) {
        // Claude Code may delete a transcript while we scan; that session is simply gone.
        if (!isVanished(err)) throw err;
      }
    }
  }
  return pick(sessions, opts.today, opts.days, floor);
}

const byNewest = (a: Session, b: Session) => (a.day === b.day ? (a.id < b.id ? -1 : 1) : a.day > b.day ? -1 : 1);

/**
 * The sessions of the last `days` days or, when those are fewer than `floor`, the `floor` most
 * recent ones, with the window widened to their real span so the server analyzes all of them.
 */
export function pick(sessions: Session[], today: string, days: number, floor: number): { window: Window; sessions: Session[] } {
  const window = windowEndingOn(today, days);
  const recent = sessions.filter((s) => s.day >= window.start && s.day <= today);
  const latest = recent.length >= floor ? [] : sessions.filter((s) => s.day <= today).sort(byNewest).slice(0, floor);
  const oldest = latest.at(-1)?.day;
  if (oldest === undefined || oldest >= window.start) return { window, sessions: recent };
  const keep = new Set(latest);
  const span = Math.round((Date.parse(today) - Date.parse(oldest)) / 86_400_000) + 1;
  return { window: windowEndingOn(today, span), sessions: sessions.filter((s) => keep.has(s)) };
}

/** Path inside the upload archive: `projects/<project>/...`, always with forward slashes. */
export function archivePath(projectsDir: string, file: string): string {
  return ["projects", ...relative(projectsDir, file).split(sep)].join("/");
}

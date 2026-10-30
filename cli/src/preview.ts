import { createReadStream, createWriteStream } from "node:fs";
import { lstat, mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";
import { archivePath, type Session, type Window, windowEndingOn } from "./collect.js";
import {
  aliasProjectDir,
  type Counts,
  type ErrorCandidate,
  redactJson,
  redactLine,
} from "./redact.js";

export const PREVIEW_META = "preview.json";
export const REPORT_FILE = "REDACTION_REPORT.md";
/** Failed calls' redacted output, for picking error lines. Stays on this machine: never packed. */
export const ERROR_CANDIDATES = "error-candidates.json";
// More failures than this keep the fixed rule's lines; a model reads the rest.
const MAX_CANDIDATES = 200;

export interface FileErrorCandidate extends ErrorCandidate {
  /** Archive path of the transcript that holds the call. */
  file: string;
}

export interface PreviewSession {
  project: string;
  id: string;
  day: string;
  /** Archive paths (`projects/...`, forward slashes) of exactly the files that will be sent. */
  paths: string[];
  bytes: number;
  counts: Counts;
}

export interface PreviewMeta {
  window: Window;
  sessions: PreviewSession[];
  counts: Counts;
  bytes: number;
  /** Failed tool calls, and how many had their error lines picked by a model instead of the fixed rule. */
  error_messages?: { failed: number; picked_by_model: number };
}

export interface WritePreviewOptions {
  projectsDir: string;
  window: Window;
  sessions: Session[];
  /** The `.revefi/` folder; previews go in its `upload-preview/<timestamp>-<random>/`. */
  revefiDir: string;
  home?: string;
  now?: Date;
  /** Keep the newest sessions whose gzipped size fits; the rest are left out and the window narrows. */
  maxCompressedBytes?: number;
}

const add = (into: Counts, from: Counts) => {
  for (const [k, v] of Object.entries(from)) into[k] = (into[k] ?? 0) + v;
};

async function redactJsonlFile(
  src: string,
  dst: string,
  counts: Counts,
  home?: string,
  errors?: ErrorCandidate[],
): Promise<number> {
  let bytes = 0;
  await pipeline(
    createReadStream(src, "utf8"),
    async function* (input) {
      for await (const line of createInterface({
        input,
        crlfDelay: Infinity,
      })) {
        const redacted = redactLine(line, counts, home, errors);
        if (redacted === undefined) continue;
        const chunk = `${redacted}\n`;
        bytes += Buffer.byteLength(chunk);
        yield chunk;
      }
    },
    createWriteStream(dst, { mode: 0o600 }),
  );
  return bytes;
}

async function redactFile(
  src: string,
  dst: string,
  counts: Counts,
  home?: string,
  errors?: ErrorCandidate[],
): Promise<number> {
  await mkdir(dirname(dst), { recursive: true, mode: 0o700 });
  if (src.endsWith(".jsonl")) return redactJsonlFile(src, dst, counts, home, errors);
  const body = redactJson(await readFile(src, "utf8"), counts, home);
  await writeFile(dst, body, { mode: 0o600 });
  return Buffer.byteLength(body);
}

/** Creates `dir` and refuses a symlink, which could send redacted transcripts outside the project. */
async function mkdirNoSymlink(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  if ((await lstat(dir)).isSymbolicLink()) {
    throw new PreviewError(`${dir} is a symlink. Remove it so the preview stays inside this project.`);
  }
}

/** Keeps redacted transcripts out of the user's git history even if `.revefi/` isn't ignored. */
export async function ensureIgnored(revefiDir: string): Promise<void> {
  await mkdirNoSymlink(revefiDir);
  const file = join(revefiDir, ".gitignore");
  const info = await lstat(file).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return undefined;
    throw err;
  });
  // A symlink here could point anywhere, so only a regular file is read and kept.
  const existing = info?.isFile() ? await readFile(file, "utf8") : "";
  const lines = existing.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  // Exact match only: git keeps leading spaces and CRs, so `  *` or `*\r` is a different rule.
  if (info?.isFile() && lines[lines.length - 1] === "*") return;
  // Git applies the last matching rule, so a trailing `*` ignores everything, even after `!` rules.
  const sep = existing && !existing.endsWith("\n") ? "\n" : "";
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, `${existing}${sep}*\n`, { flag: "wx" });
  await rename(tmp, file);
}

function uploadPath(projectsDir: string, file: string, home?: string): string {
  const [root, project, ...rest] = archivePath(projectsDir, file).split("/");
  return [root, aliasProjectDir(project ?? "", home), ...rest].join("/");
}

async function previewSession(
  dir: string,
  s: Session,
  opts: WritePreviewOptions,
  candidates: FileErrorCandidate[],
): Promise<PreviewSession> {
  const counts: Counts = {};
  const paths: string[] = [];
  let bytes = 0;
  for (const file of s.files) {
    const path = uploadPath(opts.projectsDir, file, opts.home);
    const errors: ErrorCandidate[] = [];
    bytes += await redactFile(
      file,
      join(dir, ...path.split("/")),
      counts,
      opts.home,
      errors,
    );
    candidates.push(...errors.map((c) => ({ ...c, file: path })));
    paths.push(path);
  }
  return {
    project: aliasProjectDir(s.project, opts.home),
    id: s.id,
    day: s.day,
    paths,
    bytes,
    counts,
  };
}

async function removeSession(dir: string, s: Session, home?: string): Promise<void> {
  const projectDir = join(dir, "projects", aliasProjectDir(s.project, home));
  await rm(join(projectDir, `${s.id}.jsonl`), { force: true });
  await rm(join(projectDir, s.id), { recursive: true, force: true });
}

/** Gzipped size of the files, at the level the upload archive uses: a close estimate of their share of it. */
async function gzippedSize(dir: string, paths: string[]): Promise<number> {
  let size = 0;
  const count = new Writable({
    write(chunk: Buffer, _enc, done) {
      size += chunk.length;
      done();
    },
  });
  for (const p of paths) await pipeline(createReadStream(join(dir, ...p.split("/"))), createGzip(), count, { end: false });
  return size;
}

export async function writePreview(
  opts: WritePreviewOptions,
): Promise<{ dir: string; meta: PreviewMeta }> {
  await ensureIgnored(opts.revefiDir);
  const base = join(opts.revefiDir, "upload-preview");
  await mkdirNoSymlink(base);
  const stamp = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  const dir = await mkdtemp(join(base, `${stamp}-`));
  try {
    const meta: PreviewMeta = {
      window: opts.window,
      sessions: [],
      counts: {},
      bytes: 0,
    };
    const candidates: FileErrorCandidate[] = [];
    const kept: { at: number; ps: PreviewSession; found: FileErrorCandidate[] }[] = [];
    const budget = opts.maxCompressedBytes ?? Infinity;
    let compressed = 0;
    let trimmed = false;
    const newestFirst = opts.sessions.map((s, at) => ({ s, at })).sort((a, b) => (a.s.day === b.s.day ? a.at - b.at : a.s.day > b.s.day ? -1 : 1));
    for (const { s, at } of newestFirst) {
      if (trimmed) break;
      let ps: PreviewSession;
      const found: FileErrorCandidate[] = [];
      try {
        ps = await previewSession(dir, s, opts, found);
      } catch (err) {
        // Claude Code may have deleted the session since it was found; leave it out.
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        await removeSession(dir, s, opts.home);
        continue;
      }
      if (budget !== Infinity) {
        compressed += await gzippedSize(dir, ps.paths);
        if (compressed > budget && kept.length > 0) {
          await removeSession(dir, s, opts.home);
          trimmed = true;
          continue;
        }
      }
      kept.push({ at, ps, found });
    }
    for (const { ps, found } of kept.sort((a, b) => a.at - b.at)) {
      meta.sessions.push(ps);
      add(meta.counts, ps.counts);
      meta.bytes += ps.bytes;
      candidates.push(...found);
    }
    const oldest = meta.sessions.reduce<string | undefined>((min, x) => (min === undefined || x.day < min ? x.day : min), undefined);
    if (trimmed && oldest !== undefined) {
      const span = Math.round((Date.parse(opts.window.end) - Date.parse(oldest)) / 86_400_000) + 1;
      if (span < opts.window.days) meta.window = windowEndingOn(opts.window.end, span);
    }
    if (candidates.length) {
      meta.error_messages = { failed: candidates.length, picked_by_model: 0 };
      await writeFile(
        join(dir, ERROR_CANDIDATES),
        `${JSON.stringify({ candidates: candidates.slice(0, MAX_CANDIDATES) })}\n`,
        { mode: 0o600 },
      );
    }
    await writeFile(
      join(dir, PREVIEW_META),
      `${JSON.stringify(meta, null, 2)}\n`,
      { mode: 0o600 },
    );
    await writeFile(join(dir, REPORT_FILE), renderReport(meta), {
      mode: 0o600,
    });
    return { dir, meta };
  } catch (err) {
    await rm(dir, { recursive: true, force: true });
    throw err;
  }
}

/** A preview that is missing, damaged, or asks for files outside itself. Its message is for the user. */
export class PreviewError extends Error {}

/** `projects/<project>/<file>...`: relative, forward slashes, and no `..` or empty segments. */
const SAFE_PATH = /^projects\/(?:[^/\\:]+\/)+[^/\\:]+$/;

function safePath(p: unknown): boolean {
  return typeof p === "string" && SAFE_PATH.test(p) && !p.split("/").some((seg) => seg === ".." || seg === ".");
}

export async function readPreview(dir: string): Promise<PreviewMeta> {
  const file = join(dir, PREVIEW_META);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    throw new PreviewError(`No preview at ${dir}. Previews are removed once uploaded; run \`prepare\` to make a new one.`);
  }
  let meta: Partial<PreviewMeta>;
  try {
    meta = JSON.parse(text) as Partial<PreviewMeta>;
  } catch {
    throw new PreviewError(`${file} is damaged. Run \`prepare\` again.`);
  }
  const valid =
    meta.window !== undefined &&
    Array.isArray(meta.sessions) &&
    meta.sessions.every((s) => Array.isArray(s.paths) && s.paths.every(safePath));
  if (!valid) throw new PreviewError(`${file} is not a preview this CLI wrote. Run \`prepare\` again.`);
  return meta as PreviewMeta;
}

export function humanSize(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

const RULE_LABELS: Record<string, string> = {
  "private-key": "Private key blocks",
  "anthropic-key": "Anthropic API keys",
  "openai-key": "OpenAI API keys",
  "github-token": "GitHub tokens",
  "aws-access-key": "AWS access key IDs",
  "slack-token": "Slack tokens",
  "stripe-key": "Stripe keys",
  "google-api-key": "Google API keys",
  jwt: "JSON Web Tokens",
  "bearer-token": "Bearer tokens",
  "url-credentials": "Passwords in URLs",
  "secret-assignment":
    "Values assigned to password / secret / token / key names",
  "env-file": ".env file bodies (every value masked)",
  "base64-blob": "Long base64 blobs",
  image: "Images",
  email: "Email addresses",
  phone: "Phone numbers",
  "card-number": "Payment card numbers",
  iban: "Bank account numbers (IBAN)",
  ssn: "US Social Security numbers",
  "national-id": "National ID and tax numbers (Aadhaar, PAN, UK NI, Canadian SIN)",
  "upi-id": "UPI payment IDs",
  "ip-address": "IP addresses outside private ranges",
  "home-path": "Your home folder path (shown as ~)",
  username: "Your username elsewhere, like build caches and folder names (shown as {USER})",
  "unparsable-line": "Incomplete lines (dropped)",
  "unparsable-file": "Unreadable metadata files (emptied)",
};

const cell = (s: string) => s.replace(/[|`]/g, (c) => `\\${c}`);

function errorMessagesLine({ failed, picked_by_model: picked }: { failed: number; picked_by_model: number }): string {
  const calls = `${failed} tool call${failed === 1 ? "" : "s"} failed`;
  const each = `${calls}. Each sends only its error message`;
  if (!picked) return `${each}: a few lines picked by a fixed rule.`;
  const haiku = "Claude Haiku in your Claude Code session chose which lines state the error";
  return picked >= failed ? `${each}; ${haiku}.` : `${each}. For ${picked}, ${haiku}; the rest use a fixed rule.`;
}

export function renderReport(meta: PreviewMeta): string {
  const rows = Object.entries(meta.counts)
    .sort(([, a], [, b]) => b - a)
    .map(([id, n]) => `| ${RULE_LABELS[id] ?? id} | ${n} |`);
  const sessions = [...meta.sessions]
    .sort((a, b) => b.bytes - a.bytes)
    .map(
      (s) =>
        `| ${humanSize(s.bytes)} | ${cell(s.day)} | ${cell(s.project)} | ${cell(s.id)} | ` +
        `${Object.values(s.counts).reduce((a, b) => a + b, 0)} |`,
    );
  return [
    "# What will be uploaded",
    "",
    `${meta.sessions.length} Claude Code sessions that started between ${meta.window.start} and ` +
      `${meta.window.end}, ${humanSize(meta.bytes)} after redaction. The \`projects/\` folder next to ` +
      "this file holds exactly the files that will be sent, plus a summary of their sizes and dates.",
    "",
    "## Sent as written",
    "",
    "Your prompts, Claude's replies, the commands it ran and the code it wrote are uploaded as they " +
      "are. The output of tools is not: a call that failed keeps only its error message, a few lines " +
      "at most. Redaction removes the known secret and personal-data formats listed below; it cannot " +
      "recognise every kind of sensitive text. Read through the files if a session touched something " +
      "you would not share.",
    "",
    "## Removed on this machine",
    "",
    ...(rows.length
      ? ["| What | Replaced |", "| --- | --- |", ...rows]
      : [
          "No known secret formats were found. Everything else is still sent as written.",
        ]),
    "",
    "Tool output that Claude Code saves outside the transcripts (`tool-results/`) is never uploaded.",
    "",
    ...(meta.error_messages ? [errorMessagesLine(meta.error_messages), ""] : []),
    "## Sessions, largest first",
    "",
    "| Size | Started | Project | Session | Redactions |",
    "| --- | --- | --- | --- | --- |",
    ...sessions,
    "",
    "What is in this folder is what is sent. To leave a session out, run the analysis again with " +
      "`--exclude-session <session>` rather than deleting files here, which stops the upload.",
    "",
  ].join("\n");
}

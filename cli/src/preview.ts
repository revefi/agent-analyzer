import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { pipeline } from "node:stream/promises";
import { archivePath, type Session, type Window } from "./collect.js";
import {
  aliasProjectDir,
  type Counts,
  redactJson,
  redactLine,
} from "./redact.js";

export const PREVIEW_META = "preview.json";
export const REPORT_FILE = "REDACTION_REPORT.md";

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
}

export interface WritePreviewOptions {
  projectsDir: string;
  window: Window;
  sessions: Session[];
  /** The `.revefi/` folder; previews go in its `upload-preview/<timestamp>-<random>/`. */
  revefiDir: string;
  home?: string;
  now?: Date;
}

const add = (into: Counts, from: Counts) => {
  for (const [k, v] of Object.entries(from)) into[k] = (into[k] ?? 0) + v;
};

async function redactJsonlFile(
  src: string,
  dst: string,
  counts: Counts,
  home?: string,
): Promise<number> {
  let bytes = 0;
  await pipeline(
    createReadStream(src, "utf8"),
    async function* (input) {
      for await (const line of createInterface({
        input,
        crlfDelay: Infinity,
      })) {
        const redacted = redactLine(line, counts, home);
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
): Promise<number> {
  await mkdir(dirname(dst), { recursive: true, mode: 0o700 });
  if (src.endsWith(".jsonl")) return redactJsonlFile(src, dst, counts, home);
  const body = redactJson(await readFile(src, "utf8"), counts, home);
  await writeFile(dst, body, { mode: 0o600 });
  return Buffer.byteLength(body);
}

/** Keeps redacted transcripts out of the user's git history even if `.revefi/` isn't ignored. */
async function ensureIgnored(revefiDir: string): Promise<void> {
  await mkdir(revefiDir, { recursive: true, mode: 0o700 });
  await writeFile(join(revefiDir, ".gitignore"), "*\n", { flag: "wx" }).catch(
    (err: NodeJS.ErrnoException) => {
      if (err.code !== "EEXIST") throw err;
    },
  );
}

function uploadPath(projectsDir: string, file: string, home?: string): string {
  const [root, project, ...rest] = archivePath(projectsDir, file).split("/");
  return [root, aliasProjectDir(project ?? "", home), ...rest].join("/");
}

async function previewSession(
  dir: string,
  s: Session,
  opts: WritePreviewOptions,
): Promise<PreviewSession> {
  const counts: Counts = {};
  const paths: string[] = [];
  let bytes = 0;
  for (const file of s.files) {
    const path = uploadPath(opts.projectsDir, file, opts.home);
    bytes += await redactFile(
      file,
      join(dir, ...path.split("/")),
      counts,
      opts.home,
    );
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

export async function writePreview(
  opts: WritePreviewOptions,
): Promise<{ dir: string; meta: PreviewMeta }> {
  await ensureIgnored(opts.revefiDir);
  const base = join(opts.revefiDir, "upload-preview");
  await mkdir(base, { recursive: true, mode: 0o700 });
  const stamp = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  const dir = await mkdtemp(join(base, `${stamp}-`));
  try {
    const meta: PreviewMeta = {
      window: opts.window,
      sessions: [],
      counts: {},
      bytes: 0,
    };
    for (const s of opts.sessions) {
      let ps: PreviewSession;
      try {
        ps = await previewSession(dir, s, opts);
      } catch (err) {
        // Claude Code may have deleted the session since it was found; leave it out.
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        await rm(
          join(
            dir,
            "projects",
            aliasProjectDir(s.project, opts.home),
            `${s.id}.jsonl`,
          ),
          { force: true },
        );
        await rm(
          join(dir, "projects", aliasProjectDir(s.project, opts.home), s.id),
          { recursive: true, force: true },
        );
        continue;
      }
      meta.sessions.push(ps);
      add(meta.counts, ps.counts);
      meta.bytes += ps.bytes;
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
  "original-file": "Full copies of edited files",
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
    "Your prompts, Claude's replies, the commands it ran, and the code and file contents that appear " +
      "in these sessions are uploaded as they are. Redaction removes the known secret and " +
      "personal-data formats listed below; it cannot recognise every kind of sensitive text. Read " +
      "through the files if a session touched something you would not share.",
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

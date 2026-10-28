import { realpath, stat } from "node:fs/promises";
import { join, sep } from "node:path";
import { create } from "tar";
import { humanSize, PreviewError, type PreviewMeta } from "./preview.js";

export const LIMITS = {
  maxDays: 15,
  maxCompressedBytes: 200 * 1024 * 1024,
  maxUncompressedBytes: 2 * 1024 * 1024 * 1024,
};

export interface Manifest {
  format_version: 1;
  tool: "claude-code";
  client: { name: "cli" | "plugin"; version: string };
  window: { days: number; start: string; end: string };
  session_count: number;
  bytes: { compressed: number; uncompressed: number };
}

export interface Packed {
  compressed: number;
  uncompressed: number;
}

/**
 * Writes the preview's recorded files, and nothing else in the folder, as a gzipped tar.
 * Headers are portable (no uid, gid or user names) and carry no timestamps.
 */
export async function pack(previewDir: string, meta: PreviewMeta, outFile: string): Promise<Packed> {
  const root = await realpath(previewDir);
  const paths = meta.sessions.flatMap((s) => s.paths);
  for (const p of paths) await assertInside(root, p);
  let uncompressed = 0;
  await create(
    {
      gzip: true,
      portable: true,
      noMtime: true,
      cwd: root,
      file: outFile,
      mode: 0o600,
      filter: (_path, st) => {
        if (!("isFile" in st) || !st.isFile()) return false;
        uncompressed += st.size;
        return true;
      },
    },
    paths,
  );
  return { compressed: (await stat(outFile)).size, uncompressed };
}

/** Each listed file must still exist and resolve inside the preview, even through symlinks. */
export async function assertInside(root: string, path: string, outcome = "nothing was uploaded"): Promise<void> {
  let real: string;
  try {
    real = await realpath(join(root, ...path.split("/")));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    throw new PreviewError(
      `${path} was removed from the preview, so ${outcome}. Run \`prepare\` again; ` +
        "to leave a session out, use --exclude-session.",
    );
  }
  if (!real.startsWith(root + sep)) {
    throw new PreviewError(`${path} points outside the preview folder, so ${outcome}. Run \`prepare\` again.`);
  }
}

export function buildManifest(meta: PreviewMeta, packed: Packed, client: Manifest["client"]): Manifest {
  return {
    format_version: 1,
    tool: "claude-code",
    client,
    window: meta.window,
    session_count: meta.sessions.length,
    bytes: { compressed: packed.compressed, uncompressed: packed.uncompressed },
  };
}

/** The server's limits, checked before anything is sent. Returns what to tell the user, or undefined. */
export function limitProblem(m: Pick<Manifest, "window" | "session_count" | "bytes">): string | undefined {
  if (m.window.days > LIMITS.maxDays) {
    return `The window is ${m.window.days} days; the most you can analyze at once is ${LIMITS.maxDays}. Use --days ${LIMITS.maxDays} or fewer.`;
  }
  if (m.session_count === 0) {
    const longer = m.window.days < LIMITS.maxDays ? ` or --days ${LIMITS.maxDays}` : "";
    return `No Claude Code sessions started between ${m.window.start} and ${m.window.end} here. Try --all-projects${longer}.`;
  }
  const over =
    m.bytes.compressed > LIMITS.maxCompressedBytes
      ? `${humanSize(m.bytes.compressed)} compressed; the limit is ${humanSize(LIMITS.maxCompressedBytes)}`
      : m.bytes.uncompressed > LIMITS.maxUncompressedBytes
        ? `${humanSize(m.bytes.uncompressed)} before compression; the limit is ${humanSize(LIMITS.maxUncompressedBytes)}`
        : undefined;
  if (over) {
    return (
      `The upload is ${over}. Use a shorter --days, or leave out the largest sessions ` +
      "(listed first in REDACTION_REPORT.md) with --exclude-session."
    );
  }
  return undefined;
}

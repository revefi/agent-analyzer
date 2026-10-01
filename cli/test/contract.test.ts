import { describe, expect, it } from "vitest";
import { validateManifest } from "./contract.js";

const valid = {
  format_version: 1,
  tool: "claude-code",
  client: { name: "plugin", version: "0.1.0" },
  window: { days: 7, start: "2026-09-25", end: "2026-10-01" },
  session_count: 3,
  bytes: { compressed: 1024, uncompressed: 4096 },
};

describe("contract/upload_manifest.schema.json", () => {
  it("accepts a well-formed manifest", () => {
    expect(validateManifest(valid), JSON.stringify(validateManifest.errors)).toBe(true);
  });

  it("rejects extra fields, as the server does", () => {
    expect(validateManifest({ ...valid, sampled: true })).toBe(false);
  });
});

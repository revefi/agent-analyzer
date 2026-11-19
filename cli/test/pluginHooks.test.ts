import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const plugin = join(import.meta.dirname, "../../integrations/claude-code");
const hooks = JSON.parse(readFileSync(join(plugin, "hooks/hooks.json"), "utf8")) as {
  hooks: Record<string, { matcher: string; hooks: { type: string; if?: string; command: string; args?: string[] }[] }[]>;
};

describe("plugin hooks", () => {
  it("run node on a file of the plugin, named literally, with no shell", () => {
    expect(Object.keys(hooks.hooks)).toEqual(["PostToolUse", "PostToolUseFailure"]);
    for (const event of Object.values(hooks.hooks)) {
      for (const { matcher, hooks: handlers } of event) {
        expect(matcher).toBe("Bash");
        for (const h of handlers) {
          expect(h).toMatchObject({ type: "command", if: "Bash(revefi-agent-analyzer *)", command: "node" });
          const [file, ...rest] = h.args ?? [];
          expect(file).toMatch(/^\$\{CLAUDE_PLUGIN_ROOT\}\/[\w./-]+$/);
          expect(existsSync(join(plugin, file!.replace("${CLAUDE_PLUGIN_ROOT}/", "")))).toBe(true);
          expect(rest).toEqual(["hook"]);
          // The bundle is ESM in a .js file; without this, Node before 22.7 parses it as CommonJS.
          expect(JSON.parse(readFileSync(join(plugin, "lib/package.json"), "utf8"))).toEqual({ type: "module" });
        }
      }
    }
  });
});

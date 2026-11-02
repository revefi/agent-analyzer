import { copyFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (p) => JSON.parse(readFileSync(`${root}/${p}`, "utf8"));
const { version } = read("package.json");
// Claude Code updates installed plugins only when this version changes, so releases bump both.
if (read("integrations/claude-code/.claude-plugin/plugin.json").version !== version) {
  throw new Error(`plugin.json and package.json versions differ; bump them together to ${version}.`);
}

// optimizer.revefi.com unless a dev build names another server; the CLI has no runtime override.
const api = process.env.ANALYZER_BUILD_API ?? "https://optimizer.revefi.com";
if (!/^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(api) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(api)) {
  throw new Error(`ANALYZER_BUILD_API must be an https:// origin, got ${api}.`);
}
if (api !== "https://optimizer.revefi.com") console.warn(`Dev build: talks to ${api}. Don't commit this bundle.`);

await build({
  absWorkingDir: root,
  entryPoints: ["cli/src/bin.ts"],
  outfile: "dist/revefi-agent-analyzer.js",
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  banner: { js: "#!/usr/bin/env node" },
  define: { __VERSION__: JSON.stringify(version), __API__: JSON.stringify(api) },
  legalComments: "inline",
});

// The plugin is installed from git, so it carries its own copy of the bundle.
copyFileSync(`${root}/dist/revefi-agent-analyzer.js`, `${root}/integrations/claude-code/lib/revefi-agent-analyzer.js`);

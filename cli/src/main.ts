import { parseArgs } from "node:util";

declare const __VERSION__: string;
export const VERSION = typeof __VERSION__ === "string" ? __VERSION__ : "0.0.0-dev";

export interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
}

const consoleIo: Io = { out: console.log, err: console.error };

export const USAGE = `Usage: revefi-agent-analyzer <command> [options]

Find repeated work and wasted spend in your Claude Code sessions.

Options:
  -h, --help      Show this help
  -v, --version   Show the version`;

export function main(argv: string[], io: Io = consoleIo): number {
  const [command] = argv;
  if (command === undefined || command.startsWith("-")) {
    let values;
    try {
      ({ values } = parseArgs({
        args: argv,
        options: { help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" } },
      }));
    } catch (e) {
      io.err(`${(e as Error).message}\n\n${USAGE}`);
      return 2;
    }
    io.out(values.version ? VERSION : USAGE);
    return 0;
  }
  io.err(`Unknown command: ${command}\n\n${USAGE}`);
  return 2;
}

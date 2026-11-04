const [major = 0, minor = 0] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 12)) {
  console.error(`revefi-agent-analyzer needs Node.js 22.12 or newer; you have ${process.version}. Update Node from https://nodejs.org.`);
  process.exit(1);
}

const { main } = await import("./main.js");
process.exitCode = await main(process.argv.slice(2));

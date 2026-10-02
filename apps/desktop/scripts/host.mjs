// Builds the native messaging host and puts it where the packaging step
// takes it from, so that a packaged app has the host beside its own
// program. Run by `npm run tauri:build`; a development run needs none of
// this, and finds the host where the repository's workspace builds it.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const desktop = dirname(dirname(fileURLToPath(import.meta.url)));
const repository = join(desktop, "..", "..");
const cargo = process.env.CARGO ?? "cargo";

const builtFor = /^host: (.+)$/m.exec(execFileSync("rustc", ["-vV"], { encoding: "utf8" }))?.[1];
if (!builtFor) throw new Error("rustc did not say which system it builds for");
// The packaging tool names the system the app is being built for.
const target = process.env.TAURI_ENV_TARGET_TRIPLE || builtFor;
if (target.startsWith("universal")) {
  throw new Error("the host is not built as a universal program; package for one system at a time");
}

const other = target !== builtFor;
execFileSync(cargo, ["build", "--release", "--locked", "-p", "osm-native-host", ...(other ? ["--target", target] : [])], { cwd: repository, stdio: "inherit" });

const suffix = target.includes("windows") ? ".exe" : "";
const built = join(repository, "target", ...(other ? [target] : []), "release", `osm-native-host${suffix}`);
// The packaging tool looks for the program under its name and this system.
const placed = join(desktop, "src-tauri", "binaries", `osm-native-host-${target}${suffix}`);
mkdirSync(dirname(placed), { recursive: true });
copyFileSync(built, placed);
chmodSync(placed, 0o755);
console.log(`host: ${placed}`);

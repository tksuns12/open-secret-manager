// Checks every dependency of the project against `dependency-policy.json`:
// its license must be one a GPL-3.0 program may include, and it must come
// from the official registry (or be one of this repository's own crates).
// Reads Cargo's metadata for the three Rust workspaces (the fuzz targets'
// included, though nothing in it ships) and the npm lockfiles
// of the two JavaScript packages. Prints what it found and exits with 1 if
// anything breaks the policy.
//
//   node scripts/dependencies.mjs             asks the npm registry where needed
//   node scripts/dependencies.mjs --offline   does not, and lists what it
//                                             could not check
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const policy = JSON.parse(readFileSync(path.join(root, "dependency-policy.json"), "utf8"));
const allowed = new Set(policy.licenses);
const problems = [];
const offline = process.argv.includes("--offline");
const unchecked = [];

/** Whether an SPDX expression can be satisfied with allowed licenses. */
function acceptable(expression) {
  const tokens = expression.replaceAll("/", " OR ").replaceAll("(", " ( ").replaceAll(")", " ) ").split(/\s+/).filter(Boolean);
  let at = 0;
  // or := and ("OR" and)* ; and := atom ("AND" atom)* ; atom := "(" or ")" | id ["WITH" id]
  const or = () => {
    let value = and();
    while (tokens[at] === "OR") { at += 1; const right = and(); value = value || right; }
    return value;
  };
  const and = () => {
    let value = atom();
    while (tokens[at] === "AND") { at += 1; const right = atom(); value = value && right; }
    return value;
  };
  const atom = () => {
    if (tokens[at] === "(") { at += 1; const value = or(); at += 1; return value; }
    let id = tokens[at++];
    if (tokens[at] === "WITH") { id = `${id} WITH ${tokens[at + 1]}`; at += 2; }
    return allowed.has(id);
  };
  const value = or();
  return at === tokens.length && value;
}

function checkLicense(where, name, version, license) {
  const exception = policy.exceptions[`${name}@${version}`];
  if (exception) {
    if (!Array.isArray(exception.workspaces) || !exception.workspaces.includes(where)) {
      problems.push(`${where}: ${name} ${version} is outside its allowed exception workspaces`);
      return "(disallowed exception)";
    }
    return exception.license;
  }
  if (!license) {
    problems.push(`${where}: ${name} ${version} names no license`);
    return "(none)";
  }
  if (!acceptable(license)) problems.push(`${where}: ${name} ${version} is under ${license}`);
  return license;
}

function rust(workspace, manifest) {
  const metadata = JSON.parse(execFileSync("cargo", ["metadata", "--format-version", "1", "--locked", "--manifest-path", manifest], { cwd: root, maxBuffer: 256 * 1024 * 1024, encoding: "utf8" }));
  const used = new Set(metadata.resolve.nodes.map((node) => node.id));
  const licenses = new Map();
  const versions = new Map();
  let count = 0;
  for (const crate of metadata.packages.filter((crate) => used.has(crate.id))) {
    count += 1;
    if (crate.source === null) {
      // Must be one of this repository's own crates, never a path outside the repo.
      const manifestPath = path.resolve(crate.manifest_path);
      if (!manifestPath.startsWith(root + path.sep)) {
        problems.push(`${workspace}: local crate ${crate.name} lies outside the repository (${crate.manifest_path})`);
        continue;
      }
      if (crate.license !== policy.own_license) problems.push(`${workspace}: own crate ${crate.name} is under ${crate.license}`);
      continue;
    }
    if (!policy.cargo_sources.includes(crate.source)) problems.push(`${workspace}: ${crate.name} ${crate.version} comes from ${crate.source}`);
    const license = checkLicense(workspace, crate.name, crate.version, crate.license);
    licenses.set(license, (licenses.get(license) ?? 0) + 1);
    versions.set(crate.name, [...(versions.get(crate.name) ?? []), crate.version]);
  }
  const twice = [...versions].filter(([, found]) => found.length > 1).map(([name, found]) => `${name} (${found.join(", ")})`);
  return { workspace, count, licenses, twice };
}

/** What a package says its license is: in the lockfile, or in its own
 * package.json where it is installed, or in the integrity-pinned offline map
 * in dependency-policy.json, or else in the registry when online. */
function npmLicense(workspace, folder, where, name, entry) {
  if (entry.license) return entry.license;
  try {
    const own = JSON.parse(readFileSync(path.join(root, folder, where, "package.json"), "utf8"));
    if (typeof own.license === "string") return own.license;
  } catch { /* not installed here */ }
  const pinned = policy.offline_npm_licenses?.[`${name}@${entry.version}`];
  if (pinned) {
    if (pinned.integrity !== entry.integrity) {
      problems.push(`${workspace}: ${name} ${entry.version} integrity does not match offline_npm_licenses`);
      return "(integrity mismatch)";
    }
    return pinned.license;
  }
  if (offline) return undefined;
  try {
    return JSON.parse(execFileSync("npm", ["view", `${name}@${entry.version}`, "license", "--json"], { encoding: "utf8" }));
  } catch {
    return null;
  }
}

function npm(workspace, folder) {
  const lock = JSON.parse(readFileSync(path.join(root, folder, "package-lock.json"), "utf8"));
  const licenses = new Map();
  let count = 0;
  for (const [where, entry] of Object.entries(lock.packages)) {
    if (where === "") continue;
    count += 1;
    const name = where.split("node_modules/").pop();
    if (!entry.resolved?.startsWith(policy.npm_registry) || !entry.integrity) {
      problems.push(`${workspace}: ${name} ${entry.version} comes from ${entry.resolved ?? "nowhere recorded"} ${entry.integrity ? "" : "without a checksum"}`);
    }
    const found = npmLicense(workspace, folder, where, name, entry);
    if (found === undefined) {
      unchecked.push(`${workspace}: ${name} ${entry.version}`);
      continue;
    }
    const license = checkLicense(workspace, name, entry.version, found);
    licenses.set(license, (licenses.get(license) ?? 0) + 1);
  }
  return { workspace, count, licenses, twice: [] };
}

const reports = [
  rust("Rust workspace", "Cargo.toml"),
  rust("desktop app", "apps/desktop/src-tauri/Cargo.toml"),
  rust("fuzz targets", "fuzz/Cargo.toml"),
  npm("desktop app (JavaScript)", "apps/desktop"),
  npm("browser extension (JavaScript)", "apps/browser-extension"),
];
for (const report of reports) {
  console.log(`${report.workspace}: ${report.count} dependencies`);
  for (const [license, count] of [...report.licenses].sort((a, b) => b[1] - a[1])) console.log(`  ${String(count).padStart(4)}  ${license}`);
  if (report.twice.length > 0) console.log(`  in more than one version: ${report.twice.join("; ")}`);
}
if (unchecked.length > 0) {
  for (const item of unchecked) {
    problems.push(`${item} has no verified offline license entry in dependency-policy.json`);
  }
}
if (problems.length > 0) {
  console.log(`\n${problems.length} against the policy:`);
  for (const problem of problems) console.log(`  ${problem}`);
  process.exit(1);
}
console.log("\nEvery dependency is within the policy.");

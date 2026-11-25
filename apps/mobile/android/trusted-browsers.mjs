// Writes app/src/main/res/raw/trusted_browsers.json from the list Google
// publishes of the apps a password manager may trust to report the origin
// of the web page it shows (the browsers and a few others), each with the
// SHA-256 of its release signing certificates. The autofill service
// believes a page's domain only from such an app; from any other, a domain
// in a request is just what that app says. The same apps go, in Google's
// own form, into privileged_browsers.json beside it, which Android's
// Credential Manager library reads (CallingAppInfo.getOrigin) before it
// gives the passkey provider a page's origin. Run it to update the lists
// and review the change before committing it.
//
//   node apps/mobile/android/trusted-browsers.mjs [--dry-run]
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dryRun = process.argv.includes("--dry-run");
const source = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json";
const PACKAGE_NAME = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
const SHA256_HEX = /^[0-9A-F]{64}$/;

const response = await fetch(source, {
  redirect: "error",
  signal: AbortSignal.timeout(30_000),
});
if (!response.ok) throw new Error(`${source}: ${response.status}`);
const list = await response.json();
if (!list || !Array.isArray(list.apps)) {
  throw new Error(`${source}: unexpected schema (missing apps array)`);
}

const byPackage = new Map();
for (const app of list.apps) {
  if (app?.type !== "android") continue;
  const pkg = app?.info?.package_name;
  if (typeof pkg !== "string" || !PACKAGE_NAME.test(pkg)) {
    throw new Error(`Invalid Android package name in source list: ${String(pkg)}`);
  }
  if (!Array.isArray(app.info.signatures)) {
    throw new Error(`Missing signatures array for ${pkg}`);
  }
  const hashes = new Set(byPackage.get(pkg) ?? []);
  for (const signature of app.info.signatures) {
    if (signature?.build !== "release") continue;
    if (typeof signature.cert_fingerprint_sha256 !== "string") {
      throw new Error(`Missing cert_fingerprint_sha256 for ${pkg}`);
    }
    const hex = signature.cert_fingerprint_sha256.replaceAll(":", "").toUpperCase();
    if (!SHA256_HEX.test(hex)) {
      throw new Error(`Invalid SHA-256 fingerprint for ${pkg}: ${signature.cert_fingerprint_sha256}`);
    }
    hashes.add(hex);
  }
  if (hashes.size > 0) byPackage.set(pkg, hashes);
}

const apps = [...byPackage.entries()]
  .map(([pkg, hashes]) => ({ package: pkg, sha256: [...hashes].sort() }))
  .sort((a, b) => a.package.localeCompare(b.package));
if (apps.length === 0) {
  throw new Error(`${source}: refused empty Android trusted browser list`);
}

const out = join(dirname(fileURLToPath(import.meta.url)), "app/src/main/res/raw/trusted_browsers.json");
const previous = existsSync(out) ? JSON.parse(readFileSync(out, "utf8")).apps ?? [] : [];
const prevMap = new Map(previous.map((a) => [a.package, new Set(a.sha256)]));
const nextMap = new Map(apps.map((a) => [a.package, new Set(a.sha256)]));

const addedPkgs = [...nextMap.keys()].filter((p) => !prevMap.has(p));
const removedPkgs = [...prevMap.keys()].filter((p) => !nextMap.has(p));
const changedPkgs = [...nextMap.keys()].filter((p) => {
  if (!prevMap.has(p)) return false;
  const prev = prevMap.get(p);
  const next = nextMap.get(p);
  return prev.size !== next.size || [...next].some((h) => !prev.has(h));
});

console.log(`Diff against existing trusted_browsers.json (${previous.length} -> ${apps.length} apps):`);
if (addedPkgs.length) console.log(`  + packages (${addedPkgs.length}): ${addedPkgs.join(", ")}`);
if (removedPkgs.length) console.log(`  - packages (${removedPkgs.length}): ${removedPkgs.join(", ")}`);
for (const pkg of changedPkgs) {
  const prev = prevMap.get(pkg);
  const next = nextMap.get(pkg);
  const added = [...next].filter((h) => !prev.has(h));
  const removed = [...prev].filter((h) => !next.has(h));
  console.log(`  ~ ${pkg}: +${added.length} / -${removed.length} cert(s)`);
}
if (!addedPkgs.length && !removedPkgs.length && !changedPkgs.length) {
  console.log("  (no package or certificate changes)");
}
if (dryRun) {
  console.log("Dry run: no files written.");
  process.exit(0);
}

writeFileSync(out, JSON.stringify({
  about: "Apps trusted to report the origin of the web page they show, with the SHA-256 of their release signing certificates. Made by trusted-browsers.mjs from the source; not edited by hand.",
  source,
  fetched: new Date().toISOString().slice(0, 10),
  apps,
}, null, 2) + "\n");
// Google's form, with what the library reads only: release signatures,
// of the same apps.
const privileged = join(dirname(out), "privileged_browsers.json");
writeFileSync(privileged, JSON.stringify({
  apps: apps.map((app) => ({
    type: "android",
    info: {
      package_name: app.package,
      signatures: app.sha256.map((hash) => ({
        build: "release",
        cert_fingerprint_sha256: hash.match(/../g).join(":"),
      })),
    },
  })),
}, null, 2) + "\n");
console.log(`${apps.length} apps written to ${out} and ${privileged}`);

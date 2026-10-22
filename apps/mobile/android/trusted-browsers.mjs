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
//   node apps/mobile/android/trusted-browsers.mjs
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const source = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json";
const response = await fetch(source);
if (!response.ok) throw new Error(`${source}: ${response.status}`);
const list = await response.json();
const apps = list.apps
  .filter((app) => app.type === "android")
  .map((app) => ({
    package: app.info.package_name,
    sha256: app.info.signatures
      .filter((signature) => signature.build === "release")
      .map((signature) => signature.cert_fingerprint_sha256.replaceAll(":", "").toUpperCase()),
  }))
  .filter((app) => app.sha256.length > 0)
  .sort((a, b) => a.package.localeCompare(b.package));
const out = join(dirname(fileURLToPath(import.meta.url)), "app/src/main/res/raw/trusted_browsers.json");
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

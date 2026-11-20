#!/usr/bin/env node
// Uploads a new version of the browser extension to the two stores, from
// what scripts/package-extension.sh put in dist/extension/<commit>/.
//
//   scripts/publish-extension.mjs check                 credentials work (nothing is uploaded)
//   scripts/publish-extension.mjs status                what each store holds now
//   scripts/publish-extension.mjs publish [firefox|chromium|all] [options]
//
// Options of publish:
//   --dir <folder>   the packaged folder (default: dist/extension/<this commit>)
//   --dry-run        check the package, the credentials and the versions; upload nothing
//   --staged         Chrome Web Store: hold the approved version, to publish it by hand
//   --yes            do not ask (needed where there is no terminal)
//
// Credentials are read from the environment, else from the macOS keychain
// (service osm-extension-publish, the variable's name as the account). They
// are never taken from the command line, where `ps` shows them, and never
// printed. See apps/browser-extension/README.md ("Publishing") for how to make
// them.
//
//   Firefox (addons.mozilla.org):  OSM_AMO_JWT_ISSUER, OSM_AMO_JWT_SECRET
//   Chrome Web Store:              OSM_CWS_PUBLISHER_ID, OSM_CWS_CLIENT_ID,
//                                  OSM_CWS_CLIENT_SECRET, OSM_CWS_REFRESH_TOKEN
//
// OSM_AMO_BASE, OSM_CWS_BASE, OSM_OAUTH_URL and OSM_PUBLISH_POLL_MS exist for
// the script's own test (scripts/publish-extension.test.mjs), which runs it
// against stand-in servers.
import { createHash, createHmac, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

export const AMO_SLUG = "open-secret-manager";
// The Chrome Web Store's ID for the extension (also crates/browser-link).
export const CWS_ITEM_ID = "pnjdoenkfffomcidikbkcegcpgipdjog";
export const KEYCHAIN_SERVICE = "osm-extension-publish";

// What Mozilla's reviewers are told: the add-on is bundled from TypeScript.
// Keep it as apps/browser-extension/store-listing.md says it.
export const REVIEWER_NOTES =
  "Node 24 and npm: in `apps/browser-extension`, run `npm ci && npm run build`; " +
  "`dist/firefox` is the add-on. See README.md there.";

const AMO_BASE = () => process.env.OSM_AMO_BASE ?? "https://addons.mozilla.org";
const CWS_BASE = () => process.env.OSM_CWS_BASE ?? "https://chromewebstore.googleapis.com";
const OAUTH_URL = () => process.env.OSM_OAUTH_URL ?? "https://oauth2.googleapis.com/token";
const POLL_MS = () => Number(process.env.OSM_PUBLISH_POLL_MS ?? 3000);
const POLL_LIMIT_MS = 10 * 60 * 1000;

/** What went wrong in the owner's terms; the message is all that is printed. */
export class PublishError extends Error {}

// ---------------------------------------------------------------- credentials

const NAMES = {
  firefox: ["OSM_AMO_JWT_ISSUER", "OSM_AMO_JWT_SECRET"],
  chromium: ["OSM_CWS_PUBLISHER_ID", "OSM_CWS_CLIENT_ID", "OSM_CWS_CLIENT_SECRET", "OSM_CWS_REFRESH_TOKEN"],
};

function keychain(name) {
  if (process.platform !== "darwin") return undefined;
  try {
    return execFileSync("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", name, "-w"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return undefined;
  }
}

/** The credentials of one store: from the environment, else the keychain. */
export function credentials(store) {
  const found = {};
  const missing = [];
  for (const name of NAMES[store]) {
    const value = process.env[name] || keychain(name);
    if (value) found[name] = value;
    else missing.push(name);
  }
  if (missing.length) {
    throw new PublishError(
      `No ${store === "firefox" ? "Firefox" : "Chrome Web Store"} credentials: ${missing.join(", ")} ` +
        `(in the environment, or in the keychain under the service ${KEYCHAIN_SERVICE}). ` +
        "apps/browser-extension/README.md says how to make them.",
    );
  }
  return found;
}

// ----------------------------------------------------------------------- JWT

const b64url = (input) => Buffer.from(input).toString("base64url");

/** A token for addons.mozilla.org: HS256, five minutes at most (here four). */
export function amoToken(issuer, secret, now = Math.floor(Date.now() / 1000)) {
  const head = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify({ iss: issuer, jti: randomUUID(), iat: now, exp: now + 240 }));
  const signature = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${signature}`;
}

// ------------------------------------------------------------------- the HTTP

async function call(method, url, { headers = {}, body } = {}) {
  let response;
  try {
    response = await fetch(url, { method, headers, body });
  } catch (error) {
    throw new PublishError(`${method} ${new URL(url).pathname}: ${error.cause?.code ?? error.message}`);
  }
  const text = await response.text();
  let data = text;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    // Not JSON: the text stays.
  }
  if (!response.ok) {
    const shown = (typeof data === "string" ? data : JSON.stringify(data)).slice(0, 1500);
    throw new PublishError(`${method} ${new URL(url).pathname} answered ${response.status}: ${shown}`);
  }
  return data;
}

async function until(what, step) {
  const deadline = Date.now() + POLL_LIMIT_MS;
  for (;;) {
    const result = await step();
    if (result !== undefined) return result;
    if (Date.now() > deadline) throw new PublishError(`Gave up waiting for ${what}.`);
    await new Promise((done) => setTimeout(done, POLL_MS()));
  }
}

// -------------------------------------------------------------- the package

/** Version numbers as numbers, to compare. */
export function versionParts(version) {
  const parts = String(version).split(".").map(Number);
  if (parts.length < 1 || parts.some((n) => !Number.isInteger(n) || n < 0)) {
    throw new PublishError(`Not a version number: ${version}`);
  }
  return parts;
}

export function isNewer(candidate, published) {
  const a = versionParts(candidate);
  const b = versionParts(published);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return false;
}

/**
 * The files of a packaged folder, checked against its SHA256SUMS: what
 * package-extension.sh made, and not changed since.
 */
export function readPackage(dir) {
  if (!existsSync(join(dir, "SHA256SUMS"))) {
    throw new PublishError(`${dir} has no SHA256SUMS: run scripts/package-extension.sh first.`);
  }
  const sums = new Map();
  for (const line of readFileSync(join(dir, "SHA256SUMS"), "utf8").split("\n")) {
    const match = /^([0-9a-f]{64})\s+\*?(.+)$/.exec(line.trim());
    if (match) sums.set(match[2], match[1]);
  }
  const info = existsSync(join(dir, "build-info.txt")) ? readFileSync(join(dir, "build-info.txt"), "utf8") : "";
  if (/uncommitted changes/.test(info)) {
    throw new PublishError("This package was built with uncommitted changes: it is not a release.");
  }
  const files = {};
  for (const [name, hash] of sums) {
    const match = /^open-secret-manager-(firefox|chromium|extension)-(\d+(?:\.\d+)+)(?:-source)?\.zip$/.exec(name);
    if (!match) continue;
    const bytes = readFileSync(join(dir, name));
    if (createHash("sha256").update(bytes).digest("hex") !== hash) {
      throw new PublishError(`${name} is not what SHA256SUMS says: package again.`);
    }
    files[match[1] === "extension" ? "source" : match[1]] = { name, version: match[2], bytes };
  }
  const versions = new Set(Object.values(files).map((file) => file.version));
  if (versions.size > 1) throw new PublishError(`The packages are of different versions: ${[...versions].join(", ")}.`);
  return { dir, files, version: [...versions][0], info };
}

// ------------------------------------------------------------- Firefox (AMO)

class Amo {
  constructor({ OSM_AMO_JWT_ISSUER: issuer, OSM_AMO_JWT_SECRET: secret }) {
    this.issuer = issuer;
    this.secret = secret;
  }

  headers(extra = {}) {
    return { Authorization: `JWT ${amoToken(this.issuer, this.secret)}`, ...extra };
  }

  api(path) {
    return `${AMO_BASE()}/api/v5/${path}`;
  }

  /** The add-on as the store holds it. Also what shows the key and secret are good. */
  async addon() {
    return call("GET", this.api(`addons/addon/${AMO_SLUG}/`), { headers: this.headers() });
  }

  async publishedVersion() {
    const addon = await this.addon();
    return { version: addon.current_version?.version, status: addon.status };
  }

  /** The package, then a version made of it with the source and the notes. */
  async publish(pack) {
    const file = pack.files.firefox;
    const source = pack.files.source;
    if (!file || !source) throw new PublishError("The folder has no Firefox package or no source archive.");

    const form = new FormData();
    form.append("upload", new Blob([file.bytes], { type: "application/zip" }), file.name);
    form.append("channel", "listed");
    const sent = await call("POST", this.api("addons/upload/"), { headers: this.headers(), body: form });
    const uuid = sent.uuid;
    if (!uuid) throw new PublishError("Mozilla gave no upload to follow.");
    console.log(`  uploaded ${file.name} (${uuid})`);

    const upload = await until("Mozilla to check the package", async () => {
      const state = await call("GET", this.api(`addons/upload/${uuid}/`), { headers: this.headers() });
      return state.processed ? state : undefined;
    });
    if (!upload.valid) {
      const messages = (upload.validation?.messages ?? [])
        .filter((m) => m.type === "error")
        .map((m) => `    ${m.message ?? m.id}`);
      throw new PublishError(`Mozilla refused the package:\n${messages.join("\n") || JSON.stringify(upload.validation ?? {})}`);
    }

    const version = new FormData();
    version.append("upload", uuid);
    version.append("source", new Blob([source.bytes], { type: "application/zip" }), source.name);
    const made = await call("POST", this.api(`addons/addon/${AMO_SLUG}/versions/`), {
      headers: this.headers(),
      body: version,
    });
    console.log(`  made version ${made.version} (id ${made.id}) with the source archive`);

    // The notes are a field of their own: a multipart request cannot hold the
    // complex fields, and this one goes the way the others do.
    try {
      await call("PATCH", this.api(`addons/addon/${AMO_SLUG}/versions/${made.id}/`), {
        headers: this.headers({ "Content-Type": "application/json" }),
        body: JSON.stringify({ approval_notes: REVIEWER_NOTES }),
      });
      console.log("  told the reviewers how to build it");
    } catch (error) {
      console.error(
        `  WARNING: the version is made, but the notes for the reviewers were not saved (${error.message}).\n` +
          "  Add them on the version's page on addons.mozilla.org.",
      );
    }
    return made;
  }
}

// ------------------------------------------------------- Chrome Web Store

class Cws {
  constructor(found) {
    this.publisher = found.OSM_CWS_PUBLISHER_ID;
    this.found = found;
    this.token = undefined;
  }

  async authorization() {
    if (!this.token) {
      const body = new URLSearchParams({
        client_id: this.found.OSM_CWS_CLIENT_ID,
        client_secret: this.found.OSM_CWS_CLIENT_SECRET,
        refresh_token: this.found.OSM_CWS_REFRESH_TOKEN,
        grant_type: "refresh_token",
      });
      const answer = await call("POST", OAUTH_URL(), {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      if (!answer.access_token) throw new PublishError("Google gave no access token for the refresh token.");
      this.token = answer.access_token;
    }
    return { Authorization: `Bearer ${this.token}` };
  }

  item(suffix) {
    return `${CWS_BASE()}/v2/publishers/${this.publisher}/items/${CWS_ITEM_ID}:${suffix}`;
  }

  async status() {
    return call("GET", this.item("fetchStatus"), { headers: await this.authorization() });
  }

  async publish(pack, { staged }) {
    const file = pack.files.chromium;
    if (!file) throw new PublishError("The folder has no Chromium package.");
    const headers = await this.authorization();

    const uploaded = await call("POST", `${CWS_BASE()}/upload/v2/publishers/${this.publisher}/items/${CWS_ITEM_ID}:upload`, {
      headers: { ...headers, "Content-Type": "application/zip" },
      body: file.bytes,
    });
    console.log(`  uploaded ${file.name} (${uploaded.uploadState ?? "no state"})`);
    if (uploaded.uploadState === "FAILED") throw new PublishError("The Chrome Web Store refused the upload.");
    if (uploaded.uploadState !== "SUCCEEDED") {
      await until("the Chrome Web Store to take the upload", async () => {
        const state = (await this.status()).lastAsyncUploadState;
        if (state === "IN_PROGRESS") return undefined;
        if (state !== "SUCCEEDED") throw new PublishError(`The upload ended as ${state}.`);
        return state;
      });
    }

    const answer = await call("POST", this.item("publish"), {
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ publishType: staged ? "STAGED_PUBLISH" : "DEFAULT_PUBLISH" }),
    });
    console.log(`  submitted for review (${answer.state ?? "no state"})`);
    return answer;
  }
}

// ------------------------------------------------------------------- the CLI

function parse(argv) {
  const options = { command: undefined, target: "all", dir: undefined, dryRun: false, staged: false, yes: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--dir") options.dir = argv[++i];
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--staged") options.staged = true;
    else if (arg === "--yes") options.yes = true;
    else if (arg.startsWith("--")) throw new PublishError(`Unknown option ${arg}.`);
    else rest.push(arg);
  }
  options.command = rest[0];
  if (rest[1]) options.target = rest[1];
  if (!["check", "status", "publish"].includes(options.command)) {
    throw new PublishError("Usage: publish-extension.mjs check | status | publish [firefox|chromium|all] [--dir F] [--dry-run] [--staged] [--yes]");
  }
  if (!["firefox", "chromium", "all"].includes(options.target)) throw new PublishError(`Not a store: ${options.target}`);
  return options;
}

const storesOf = (target) => (target === "all" ? ["firefox", "chromium"] : [target]);

function defaultDir() {
  const short = execFileSync("git", ["rev-parse", "--short", "HEAD"], { encoding: "utf8" }).trim();
  return resolve(fileURLToPath(new URL("..", import.meta.url)), "dist", "extension", short);
}

async function confirm(summary, options) {
  console.log(summary);
  if (options.yes) return;
  if (!process.stdin.isTTY) {
    throw new PublishError("There is no terminal to ask on: look at the plan above, then run again with --yes.");
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question("Upload these? Type yes: ");
  rl.close();
  if (answer.trim() !== "yes") throw new PublishError("Not uploaded.");
}

export async function main(argv) {
  const options = parse(argv);
  const stores = storesOf(options.target);

  if (options.command === "check" || options.command === "status") {
    for (const store of stores) {
      if (store === "firefox") {
        const { version, status } = await new Amo(credentials("firefox")).publishedVersion();
        console.log(`Firefox: credentials work; published version ${version ?? "none"}, add-on status ${status}.`);
      } else {
        const state = await new Cws(credentials("chromium")).status();
        const published = state.publishedItemRevisionStatus?.state ?? "none";
        const submitted = state.submittedItemRevisionStatus?.state ?? "none";
        console.log(`Chrome Web Store: credentials work; published ${published}, submitted ${submitted}.`);
      }
    }
    return;
  }

  const pack = readPackage(resolve(options.dir ?? defaultDir()));
  const have = stores.filter((store) => pack.files[store]);
  if (have.length !== stores.length) {
    throw new PublishError(`${pack.dir} has no package for ${stores.filter((s) => !pack.files[s]).join(", ")}.`);
  }
  const amo = stores.includes("firefox") ? new Amo(credentials("firefox")) : undefined;
  const cws = stores.includes("chromium") ? new Cws(credentials("chromium")) : undefined;

  if (amo) {
    const { version } = await amo.publishedVersion();
    if (version && !isNewer(pack.version, version)) {
      throw new PublishError(`Firefox already has ${version}: ${pack.version} is not newer. Raise the version in the manifests and package again.`);
    }
  }
  if (cws) await cws.status();

  const lines = [`Extension ${pack.version}, from ${pack.dir}`];
  lines.push(...pack.info.split("\n").filter((l) => l.startsWith("commit")).map((l) => `  ${l}`));
  for (const store of stores) {
    const file = pack.files[store];
    const hash = createHash("sha256").update(file.bytes).digest("hex").slice(0, 16);
    lines.push(`  ${store === "firefox" ? "Firefox" : "Chrome Web Store"}: ${file.name} (sha256 ${hash}…)` +
      (store === "chromium" ? (options.staged ? ", held for you to publish" : ", published when approved") : ", listed, with the source archive"));
  }
  if (options.dryRun) {
    console.log(lines.join("\n"));
    console.log("Dry run: the package and the credentials are good; nothing was uploaded.");
    return;
  }
  await confirm(lines.join("\n"), options);

  for (const store of stores) {
    console.log(store === "firefox" ? "Firefox:" : "Chrome Web Store:");
    if (store === "firefox") await amo.publish(pack);
    else await cws.publish(pack, { staged: options.staged });
  }
  console.log("Done. Both stores review it before it is public; their mail says when.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof PublishError ? error.message : error);
    process.exit(1);
  });
}
